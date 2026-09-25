#!/usr/bin/env python3
"""Extract changed Python function pairs from reviewed GitHub fix commits.

The input is the candidate inventory produced by ``discover_cwe_candidates.py``.
Only candidates marked READY_FOR_EXTRACTION are fetched.  The output remains a
curation input: extraction success does not imply that a sample is accepted.
"""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
import re
import tempfile
import textwrap
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping


COMMIT_RE = re.compile(
    r"^https://github\.com/([^/]+)/([^/]+)/commit/([0-9a-f]{7,64})",
    re.IGNORECASE,
)
DIFF_RE = re.compile(r"^diff --git a/(.+) b/(.+)$")
HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
REVIEW_PARTS = {"test", "tests", "docs", "examples", "vendor", "generated", "migrations"}
LABEL_BY_CWE = {
    "CWE-22": "PATH_TRAVERSAL",
    "CWE-78": "COMMAND_INJECTION",
    "CWE-79": "XSS",
    "CWE-89": "SQL_INJECTION",
    "CWE-287": "INSECURE_AUTHENTICATION",
    "CWE-798": "HARDCODED_CREDENTIALS",
}


@dataclass
class ChangedFile:
    old_path: str
    new_path: str
    old_lines: set[int] = field(default_factory=set)
    new_lines: set[int] = field(default_factory=set)


@dataclass(frozen=True)
class FunctionSpan:
    qualified_name: str
    start: int
    end: int
    code: str


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"Expected object at {path}:{number}")
            rows.append(row)
    return rows


def atomic_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", delete=False, dir=path.parent
    ) as handle:
        temporary = Path(handle.name)
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    temporary.replace(path)


class CachedGitHubClient:
    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "PyVul-dataset-curation",
        }

    def _get(self, url: str, cache_name: str, *, binary: bool = False) -> bytes | str:
        cache_path = self.cache_dir / cache_name
        if cache_path.exists():
            data = cache_path.read_bytes()
        else:
            request = urllib.request.Request(url, headers=self.headers)
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read()
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_bytes(data)
        return data if binary else data.decode("utf-8", errors="replace")

    def commit(self, repository: str, commit_id: str) -> dict[str, Any]:
        payload = self._get(
            f"https://api.github.com/repos/{repository}/commits/{commit_id}",
            f"commits/{repository.replace('/', '__')}__{commit_id}.json",
        )
        row = json.loads(str(payload))
        if not isinstance(row, dict):
            raise ValueError("Unexpected commit API response")
        return row

    def diff(self, repository: str, commit_id: str) -> str:
        return str(
            self._get(
                f"https://github.com/{repository}/commit/{commit_id}.diff",
                f"diffs/{repository.replace('/', '__')}__{commit_id}.diff",
            )
        )

    def raw(self, repository: str, revision: str, path: str) -> str:
        quoted = "/".join(urllib.parse.quote(part) for part in path.split("/"))
        key = hashlib.sha256(f"{repository}@{revision}:{path}".encode()).hexdigest()
        return str(
            self._get(
                f"https://raw.githubusercontent.com/{repository}/{revision}/{quoted}",
                f"raw/{key}.py",
            )
        )


def parse_diff(text: str) -> list[ChangedFile]:
    files: list[ChangedFile] = []
    current: ChangedFile | None = None
    old_line = new_line = 0
    hunk_old_start = hunk_new_start = 0
    hunk_old_changed = hunk_new_changed = False

    def finish_hunk() -> None:
        nonlocal hunk_old_changed, hunk_new_changed
        if current is None:
            return
        if hunk_old_start and not hunk_old_changed:
            current.old_lines.add(max(1, hunk_old_start))
        if hunk_new_start and not hunk_new_changed:
            current.new_lines.add(max(1, hunk_new_start))
        hunk_old_changed = hunk_new_changed = False

    for raw_line in text.splitlines():
        file_match = DIFF_RE.match(raw_line)
        if file_match:
            finish_hunk()
            current = ChangedFile(file_match.group(1), file_match.group(2))
            files.append(current)
            old_line = new_line = hunk_old_start = hunk_new_start = 0
            continue
        hunk_match = HUNK_RE.match(raw_line)
        if hunk_match and current is not None:
            finish_hunk()
            old_line = hunk_old_start = int(hunk_match.group(1))
            new_line = hunk_new_start = int(hunk_match.group(3))
            continue
        if current is None or not hunk_old_start:
            continue
        if raw_line.startswith("-") and not raw_line.startswith("---"):
            current.old_lines.add(old_line)
            hunk_old_changed = True
            old_line += 1
        elif raw_line.startswith("+") and not raw_line.startswith("+++"):
            current.new_lines.add(new_line)
            hunk_new_changed = True
            new_line += 1
        elif raw_line.startswith(" "):
            old_line += 1
            new_line += 1
    finish_hunk()
    return files


class FunctionCollector(ast.NodeVisitor):
    def __init__(self, source: str) -> None:
        self.source = source
        self.lines = source.splitlines(keepends=True)
        self.stack: list[str] = []
        self.functions: list[FunctionSpan] = []

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        start = min([node.lineno] + [item.lineno for item in node.decorator_list])
        end = int(node.end_lineno or node.lineno)
        name = ".".join([*self.stack, node.name])
        code = "".join(self.lines[start - 1 : end])
        self.functions.append(FunctionSpan(name, start, end, code))
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._visit_function(node)


def collect_functions(source: str) -> list[FunctionSpan]:
    tree = ast.parse(source)
    collector = FunctionCollector(source)
    collector.visit(tree)
    return collector.functions


def module_binding_block(source: str, binding: str) -> tuple[FunctionSpan, list[dict[str, int]]] | None:
    """Take an exact top-level binding and its local definition dependencies.

    This is deliberately opt-in for curated CWE-798 candidates. It does not
    turn an entire module or an unrelated changed function into a training row.
    """
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    definitions: dict[str, ast.stmt] = {}
    assignment: ast.stmt | None = None
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            definitions[node.name] = node
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    definitions[target.id] = node
                    if target.id == binding:
                        assignment = node
    if assignment is None:
        return None
    selected: dict[int, ast.stmt] = {}

    def include(node: ast.stmt) -> None:
        if id(node) in selected:
            return
        selected[id(node)] = node
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                dependency = definitions.get(child.id)
                if dependency is not None and dependency is not node:
                    include(dependency)

    include(assignment)
    # A later module-level branch may overwrite the binding. Omitting that
    # branch would make an unsafe fixed version look safe (for example, an
    # explicit development mode that restores a public JWT signing key).
    for node in tree.body:
        if node is assignment or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if any(
            isinstance(child, ast.Name)
            and child.id == binding
            and isinstance(child.ctx, ast.Store)
            for child in ast.walk(node)
        ):
            include(node)
    ordered = sorted(selected.values(), key=lambda node: node.lineno)
    spans = [
        {"start_line": int(node.lineno), "end_line": int(node.end_lineno or node.lineno)}
        for node in ordered
    ]
    code = "\n\n".join(
        "".join(lines[span["start_line"] - 1 : span["end_line"]]).rstrip("\n")
        for span in spans
    ) + "\n"
    return FunctionSpan(f"module:{binding}", spans[0]["start_line"], spans[-1]["end_line"], code), spans


def affected(functions: Iterable[FunctionSpan], changed_lines: set[int]) -> dict[str, FunctionSpan]:
    result: dict[str, FunctionSpan] = {}
    for function in functions:
        if any(function.start <= line <= function.end for line in changed_lines):
            result[function.qualified_name] = function
    return result


def is_review_path(path: str) -> bool:
    parts = {part.lower() for part in Path(path).parts}
    name = Path(path).name.lower()
    return bool(parts & REVIEW_PARTS or name.startswith("test_") or name.endswith("_test.py"))


def make_pair(
    candidate: Mapping[str, Any],
    repository: str,
    commit_id: str,
    parent_id: str,
    commit_message: str | None,
    file: ChangedFile,
    before: FunctionSpan,
    after: FunctionSpan,
    sequence: int,
    *,
    unit_type: str = "function",
    source_spans_before: list[dict[str, int]] | None = None,
    source_spans_after: list[dict[str, int]] | None = None,
) -> dict[str, Any]:
    ghsa = str(candidate.get("ghsa_id") or "UNKNOWN")
    cve = candidate.get("cve_id")
    advisory_cwes = sorted({str(value) for value in candidate.get("cwes") or []})
    target_cwe = str(candidate.get("target_cwe") or "")
    isolated_cwe = str(candidate.get("isolated_target_cwe") or "")
    cwes = [isolated_cwe] if isolated_cwe else (advisory_cwes or ([target_cwe] if target_cwe else []))
    labels = [LABEL_BY_CWE[cwe] for cwe in cwes if cwe in LABEL_BY_CWE]
    sample_cwe = target_cwe.replace("-", "") or "CWE_UNKNOWN"
    identity = f"{repository}@{commit_id}:{file.new_path}:{after.qualified_name}"
    digest = hashlib.sha256(identity.encode()).hexdigest()[:16]
    return {
        "schema_version": "1.0",
        "sample_id": f"GHSA_{sample_cwe}_{sequence:04d}_{digest}",
        "source_dataset": "GitHub Advisory Database",
        "source_dataset_url": "https://github.com/advisories",
        "source_license": "CC-BY-4.0 advisory metadata; source code retains repository license",
        "source_record_id": ghsa,
        "advisory_ids": [value for value in (ghsa, cve) if value],
        "advisory_url": candidate.get("advisory_url"),
        "repository": repository,
        "parent_commit_id": parent_id,
        "commit_id": commit_id,
        "commit_url": f"https://github.com/{repository}/commit/{commit_id}",
        "file_path": file.new_path,
        "function_name": after.qualified_name,
        "unit_type": unit_type,
        "start_line_before": before.start,
        "end_line_before": before.end,
        "start_line_after": after.start,
        "end_line_after": after.end,
        "source_spans_before": source_spans_before or [{"start_line": before.start, "end_line": before.end}],
        "source_spans_after": source_spans_after or [{"start_line": after.start, "end_line": after.end}],
        "language": "Python",
        "cwes": cwes,
        "advisory_cwes": advisory_cwes,
        "cwe_isolation_evidence": candidate.get("cwe_isolation_evidence") if isolated_cwe else None,
        "labels": labels,
        "code_before": before.code,
        "code_after": after.code,
        "changed_lines_before": sorted(file.old_lines),
        "changed_lines_after": sorted(file.new_lines),
        "commit_message": commit_message,
        "description": candidate.get("summary"),
        "extraction_method": "github_fix_commit_ast_changed_module_block" if unit_type == "module_block" else "github_fix_commit_ast_changed_function",
        "platform": candidate.get("platform"),
        "vulnerability_scope": candidate.get("vulnerability_scope"),
        "domain": candidate.get("domain"),
        "curation_status": candidate.get("curation_status"),
        "curation_notes": candidate.get("curation_notes"),
    }


def extract_candidates(
    candidates: list[dict[str, Any]], client: CachedGitHubClient
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    pairs: list[dict[str, Any]] = []
    review: list[dict[str, Any]] = []
    sequence = 0
    for candidate in candidates:
        if candidate.get("candidate_status") != "READY_FOR_EXTRACTION":
            continue
        include_functions = {
            str(value) for value in candidate.get("include_functions") or []
        }
        include_module_bindings = {
            str(value) for value in candidate.get("include_module_bindings") or []
        }
        advisory_cwes = sorted({str(value) for value in candidate.get("cwes") or []})
        isolated_cwe = str(candidate.get("isolated_target_cwe") or "")
        include_module_files = {str(value) for value in candidate.get("include_module_files") or []}
        if isolated_cwe and not include_module_bindings:
            review.append({"ghsa_id": candidate.get("ghsa_id"), "reason": "rejected_isolated_cwe_requires_module_binding_scope"})
            continue
        if include_module_bindings:
            exact = advisory_cwes == ["CWE-798"] and not isolated_cwe
            curated_multi = (
                len(advisory_cwes) > 1
                and "CWE-798" in advisory_cwes
                and isolated_cwe == "CWE-798"
                and candidate.get("target_cwe") == "CWE-798"
                and candidate.get("curation_status") == "APPROVED_FOR_STAGING"
                and bool(str(candidate.get("cwe_isolation_evidence") or "").strip())
                and bool(include_module_files)
            )
            if not (exact or curated_multi):
                review.append({"ghsa_id": candidate.get("ghsa_id"), "reason": "rejected_module_scope_without_cwe798_isolation_evidence"})
                continue
        for fix in candidate.get("fix_commits") or []:
            repository = str(fix.get("repository") or "")
            commit_id = str(fix.get("commit_id") or "")
            base = {
                "ghsa_id": candidate.get("ghsa_id"),
                "cve_id": candidate.get("cve_id"),
                "repository": repository,
                "commit_id": commit_id,
                "commit_url": fix.get("commit_url"),
            }
            try:
                commit = client.commit(repository, commit_id)
                parents = commit.get("parents") or []
                if len(parents) != 1:
                    review.append({**base, "reason": "manual_review_non_single_parent_commit"})
                    continue
                parent_id = str(parents[0].get("sha") or "")
                message = ((commit.get("commit") or {}).get("message"))
                changed_files = parse_diff(client.diff(repository, commit_id))
                python_files = [
                    row
                    for row in changed_files
                    if row.old_path.endswith(".py") and row.new_path.endswith(".py")
                    and not is_review_path(row.new_path)
                ]
                if not python_files:
                    review.append({**base, "reason": "rejected_no_production_python_file"})
                    continue
                commit_pairs = 0
                for file in python_files:
                    if include_module_files and file.new_path not in include_module_files:
                        continue
                    try:
                        before_source = client.raw(repository, parent_id, file.old_path)
                        after_source = client.raw(repository, commit_id, file.new_path)
                        before_map = affected(collect_functions(before_source), file.old_lines) if not include_module_bindings else {}
                        after_map = affected(collect_functions(after_source), file.new_lines) if not include_module_bindings else {}
                    except (SyntaxError, urllib.error.HTTPError, urllib.error.URLError) as exc:
                        review.append(
                            {**base, "file_path": file.new_path, "reason": "manual_review_source_or_ast_error", "detail": str(exc)}
                        )
                        continue
                    common = sorted(set(before_map) & set(after_map))
                    if not common and not include_module_bindings:
                        review.append(
                            {**base, "file_path": file.new_path, "reason": "manual_review_no_paired_changed_function"}
                        )
                        continue
                    for name in common:
                        if before_map[name].code == after_map[name].code:
                            continue
                        if include_functions and name not in include_functions:
                            review.append(
                                {
                                    **base,
                                    "file_path": file.new_path,
                                    "function_name": name,
                                    "reason": "excluded_by_batch_function_allowlist",
                                }
                            )
                            continue
                        sequence += 1
                        pairs.append(
                            make_pair(
                                candidate,
                                repository,
                                commit_id,
                                parent_id,
                                str(message) if message else None,
                                file,
                                before_map[name],
                                after_map[name],
                                sequence,
                            )
                        )
                        commit_pairs += 1
                    for binding in sorted(include_module_bindings):
                        before_block = module_binding_block(before_source, binding)
                        after_block = module_binding_block(after_source, binding)
                        if before_block is None or after_block is None:
                            review.append({**base, "file_path": file.new_path, "binding": binding, "reason": "manual_review_missing_module_binding"})
                            continue
                        before_span, before_locations = before_block
                        after_span, after_locations = after_block
                        if not any(before_span.start <= line <= before_span.end for line in file.old_lines) or not any(after_span.start <= line <= after_span.end for line in file.new_lines):
                            continue
                        if before_span.code == after_span.code:
                            continue
                        sequence += 1
                        pairs.append(make_pair(candidate, repository, commit_id, parent_id, str(message) if message else None, file, before_span, after_span, sequence, unit_type="module_block", source_spans_before=before_locations, source_spans_after=after_locations))
                        commit_pairs += 1
                if not commit_pairs:
                    review.append({**base, "reason": "manual_review_commit_produced_no_pair"})
            except Exception as exc:  # keep the batch auditable instead of aborting it
                review.append({**base, "reason": "manual_review_download_or_parse_error", "detail": str(exc)})
    return pairs, review


def write_summary(path: Path, pairs: list[dict[str, Any]], review: list[dict[str, Any]]) -> None:
    rows = [
        {"metric": "normalized_function_pairs", "value": len(pairs)},
        {"metric": "review_records", "value": len(review)},
        {"metric": "unique_repositories", "value": len({row["repository"] for row in pairs})},
        {"metric": "unique_commits", "value": len({row["commit_id"] for row in pairs})},
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["metric", "value"])
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/supplement/cwe-798/advisory_candidates.jsonl"),
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("data/supplement/cwe-798")
    )
    parser.add_argument(
        "--cache-dir", type=Path, default=Path("data/supplement/cwe-798/cache")
    )
    args = parser.parse_args()
    candidates = read_jsonl(args.input)
    pairs, review = extract_candidates(candidates, CachedGitHubClient(args.cache_dir))
    atomic_jsonl(args.output_dir / "normalized_pairs.jsonl", pairs)
    atomic_jsonl(args.output_dir / "extraction_review.jsonl", review)
    write_summary(args.output_dir / "extraction_summary.csv", pairs, review)
    print(f"Extracted {len(pairs)} normalized function pairs")
    print(f"Review records: {len(review)}")
    print(f"Wrote outputs to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
