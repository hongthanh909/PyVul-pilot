#!/usr/bin/env python3
"""Recover missing PyVul file paths from GitHub fixing-commit diffs.

The released function-level dataset retains ``file_change_id`` but drops the
corresponding filename/old_path/new_path fields.  This script conservatively
reconstructs that mapping by matching the vulnerable/fixed function code to
files in each fixing commit's unified diff.

Only unique, high-confidence matches are written to file_metadata.jsonl.
Ambiguous and failed cases are kept in CSV reports for manual review.  Remote
diffs are cached, so interrupted runs can be resumed without starting over.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Sequence

try:  # Direct execution: python scripts/recover_file_paths.py
    from filter_pyvul import TARGETS, normalize_commit, normalize_cwes
except ModuleNotFoundError:  # Package import used by tests and other scripts
    from scripts.filter_pyvul import TARGETS, normalize_commit, normalize_cwes


DEFAULT_FUNCTION_DATASET = Path("dataset/function_level_dataset.out")
DEFAULT_CWE_MAP = Path("dataset/commits_cwe_map.json")
DEFAULT_OUTPUT = Path("dataset/file_metadata.jsonl")
DEFAULT_REPORT_DIR = Path("data/recovery")


class RecoveryError(RuntimeError):
    """A fatal local input/configuration error."""


@dataclass
class DiffFile:
    old_path: str | None
    new_path: str | None
    patch_lines: list[str] = field(default_factory=list)
    deleted: set[str] = field(default_factory=set)
    added: set[str] = field(default_factory=set)
    context: set[str] = field(default_factory=set)

    @property
    def preferred_path(self) -> str | None:
        return self.new_path or self.old_path


@dataclass(frozen=True)
class CandidateScore:
    path: str
    old_path: str | None
    new_path: str | None
    score: int
    deleted_hits: int
    added_hits: int
    context_hits: int
    function_name_hits: int


def meaningful_line(value: str) -> str:
    """Normalize layout for robust line matching without changing identifiers."""
    return " ".join(value.strip().split())


def code_lines(code: Any) -> set[str]:
    if not isinstance(code, str):
        return set()
    result = set()
    for raw_line in code.splitlines():
        line = meaningful_line(raw_line)
        if not line or line.startswith("#"):
            continue
        # Braces and punctuation-only lines are too common to identify a file.
        if not re.search(r"[A-Za-z0-9_]", line):
            continue
        result.add(line)
    return result


def decode_git_path(value: str) -> str | None:
    value = value.strip()
    if value == "/dev/null":
        return None
    if value.startswith('"') and value.endswith('"'):
        try:
            value = bytes(value[1:-1], "utf-8").decode("unicode_escape")
        except UnicodeDecodeError:
            value = value[1:-1]
    if value.startswith("a/") or value.startswith("b/"):
        value = value[2:]
    return value or None


def diff_header_paths(line: str) -> tuple[str | None, str | None]:
    payload = line[len("diff --git ") :]
    # Git quotes paths containing spaces. This expression handles the normal
    # unquoted case and quoted paths without requiring shell parsing.
    match = re.match(r'("(?:\\.|[^"\\])*"|\S+)\s+("(?:\\.|[^"\\])*"|\S+)$', payload)
    if not match:
        return None, None
    return decode_git_path(match.group(1)), decode_git_path(match.group(2))


def parse_unified_diff(text: str) -> list[DiffFile]:
    files: list[DiffFile] = []
    current: DiffFile | None = None
    in_hunk = False
    for line in text.splitlines():
        if line.startswith("diff --git "):
            old_path, new_path = diff_header_paths(line)
            current = DiffFile(old_path=old_path, new_path=new_path)
            files.append(current)
            in_hunk = False
            continue
        if current is None:
            continue
        current.patch_lines.append(line)
        if line.startswith("--- "):
            current.old_path = decode_git_path(line[4:].split("\t", 1)[0])
            continue
        if line.startswith("+++ "):
            current.new_path = decode_git_path(line[4:].split("\t", 1)[0])
            continue
        if line.startswith("@@"):
            in_hunk = True
            continue
        if not in_hunk or not line:
            continue
        prefix, content = line[0], meaningful_line(line[1:])
        if not content or not re.search(r"[A-Za-z0-9_]", content):
            continue
        if prefix == "-":
            current.deleted.add(content)
        elif prefix == "+":
            current.added.add(content)
        elif prefix == " ":
            current.context.add(content)
    return [item for item in files if item.preferred_path]


def score_file(rows: Sequence[Mapping[str, Any]], diff_file: DiffFile) -> CandidateScore:
    before = set().union(*(code_lines(row.get("code_before")) for row in rows))
    after = set().union(*(code_lines(row.get("code_after")) for row in rows))
    names = {
        str(row.get("function_name") or "").strip()
        for row in rows
        if str(row.get("function_name") or "").strip()
    }
    deleted_hits = len(before & diff_file.deleted)
    added_hits = len(after & diff_file.added)
    context_hits = len((before | after) & diff_file.context)
    patch_text = "\n".join(diff_file.patch_lines)
    name_hits = sum(bool(re.search(rf"\b{re.escape(name)}\b", patch_text)) for name in names)
    # Changed lines are strongest; context/name matches only break close ties.
    score = 10 * (deleted_hits + added_hits) + min(context_hits, 6) + 2 * name_hits
    return CandidateScore(
        path=str(diff_file.preferred_path),
        old_path=diff_file.old_path,
        new_path=diff_file.new_path,
        score=score,
        deleted_hits=deleted_hits,
        added_hits=added_hits,
        context_hits=context_hits,
        function_name_hits=name_hits,
    )


def choose_candidate(
    rows: Sequence[Mapping[str, Any]], files: Sequence[DiffFile]
) -> tuple[CandidateScore | None, str, list[CandidateScore]]:
    expected_python = any(
        str(row.get("programming_language") or "").strip().lower() in {"python", "py", "python3"}
        for row in rows
    )
    candidates = [
        score_file(rows, item)
        for item in files
        if not expected_python or str(item.preferred_path).lower().endswith(".py")
    ]
    candidates.sort(key=lambda item: (-item.score, item.path))
    if not candidates or candidates[0].score == 0:
        return None, "no_code_match", candidates

    best = candidates[0]
    second_score = candidates[1].score if len(candidates) > 1 else -1
    has_before = any(bool(str(row.get("code_before") or "").strip()) for row in rows)
    has_after = any(bool(str(row.get("code_after") or "").strip()) for row in rows)
    changed_side_match = (
        (not has_before or best.deleted_hits > 0)
        and (not has_after or best.added_hits > 0)
    )
    if not changed_side_match:
        return None, "missing_before_or_after_change_match", candidates
    if best.score == second_score:
        return None, "ambiguous_equal_score", candidates
    if best.deleted_hits + best.added_hits < 2 and best.function_name_hits == 0:
        return None, "weak_match", candidates
    return best, "unique_high_confidence_diff_match", candidates


def load_inputs(
    function_path: Path,
    cwe_map_path: Path,
    *,
    target_only: bool,
    python_only: bool,
) -> tuple[dict[str, list[dict[str, Any]]], int]:
    try:
        cwe_map_raw = json.loads(cwe_map_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RecoveryError(f"Cannot read {cwe_map_path}: {exc}") from exc
    normalized_map: dict[str, list[str]] = {}
    for url, value in cwe_map_raw.items():
        info = normalize_commit(url)
        if info["join_key"]:
            normalized_map[str(info["join_key"])] = normalize_cwes(value)

    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    input_count = 0
    try:
        handle = function_path.open("r", encoding="utf-8-sig")
    except OSError as exc:
        raise RecoveryError(f"Cannot read {function_path}: {exc}") from exc
    with handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            input_count += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RecoveryError(f"Invalid JSON at {function_path}:{line_number}: {exc}") from exc
            commit = normalize_commit(row.get("commit"))
            join_key = str(commit.get("join_key") or "")
            cwes = normalized_map.get(join_key, [])
            if target_only and not any(cwe in TARGETS for cwe in cwes):
                continue
            language = str(row.get("programming_language") or "").strip().lower()
            if python_only and language not in {"python", "py", "python3"}:
                continue
            file_change_id = str(row.get("file_change_id") or "")
            if not join_key or not file_change_id:
                continue
            row["_source_line"] = line_number
            row["_cwes"] = cwes
            row["_commit_info"] = commit
            groups[f"{join_key}|{file_change_id}"].append(row)
    return dict(groups), input_count


class DiffDownloader:
    def __init__(self, cache_dir: Path, timeout: int, retries: int) -> None:
        self.cache_dir = cache_dir
        self.timeout = timeout
        self.retries = retries
        cache_dir.mkdir(parents=True, exist_ok=True)

    def cache_path(self, commit_info: Mapping[str, Any]) -> Path:
        repository = str(commit_info.get("repository_id") or "unknown").replace("/", "__")
        commit_id = str(commit_info.get("commit_id") or "unknown")
        return self.cache_dir / f"{repository}__{commit_id}.diff"

    def get(self, commit_info: Mapping[str, Any], *, refresh: bool = False) -> tuple[str, bool]:
        cache_path = self.cache_path(commit_info)
        if cache_path.is_file() and not refresh:
            return cache_path.read_text(encoding="utf-8", errors="replace"), True
        canonical = str(commit_info.get("canonical_url") or "").rstrip("/")
        if not canonical:
            raise RecoveryError("Commit has no canonical URL")
        url = canonical + ".diff"
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "text/plain",
                "User-Agent": "PyVul-file-path-recovery/1.0",
            },
        )
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    data = response.read()
                text = data.decode("utf-8", errors="replace")
                if not text.startswith("diff --git "):
                    raise RecoveryError(f"Response for {url} is not a Git diff")
                temporary = cache_path.with_suffix(cache_path.suffix + ".tmp")
                temporary.write_text(text, encoding="utf-8", newline="\n")
                os.replace(temporary, cache_path)
                return text, False
            except (OSError, urllib.error.URLError, RecoveryError) as exc:
                last_error = exc
                if attempt < self.retries:
                    time.sleep(min(2**attempt, 8))
        raise RecoveryError(f"Cannot download {url}: {last_error}")


def atomic_write_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def write_csv(path: Path, fieldnames: Sequence[str], rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def recover(args: argparse.Namespace) -> tuple[list[dict[str, Any]], list[dict[str, Any]], Counter[str]]:
    groups, input_count = load_inputs(
        args.function_dataset,
        args.cwe_map,
        target_only=args.target_only,
        python_only=args.python_only,
    )
    by_commit: dict[str, list[tuple[str, list[dict[str, Any]]]]] = defaultdict(list)
    for group_key, rows in groups.items():
        join_key = str(rows[0]["_commit_info"]["join_key"])
        by_commit[join_key].append((group_key, rows))

    downloader = DiffDownloader(args.cache_dir, args.timeout, args.retries)
    resolved: list[dict[str, Any]] = []
    unresolved: list[dict[str, Any]] = []
    stats: Counter[str] = Counter()
    stats["input_rows"] = input_count
    stats["selected_groups"] = len(groups)
    stats["selected_commits"] = len(by_commit)

    total = len(by_commit)
    for commit_number, (join_key, commit_groups) in enumerate(sorted(by_commit.items()), 1):
        commit_info = commit_groups[0][1][0]["_commit_info"]
        print(f"[{commit_number}/{total}] {join_key}", flush=True)
        try:
            diff_text, from_cache = downloader.get(commit_info, refresh=args.refresh)
            stats["cached_commits" if from_cache else "downloaded_commits"] += 1
            files = parse_unified_diff(diff_text)
            if not files:
                raise RecoveryError("Commit diff contains no parseable files")
        except RecoveryError as exc:
            stats["download_or_parse_failures"] += 1
            for group_key, rows in commit_groups:
                unresolved.append(
                    {
                        "file_change_id": rows[0].get("file_change_id"),
                        "commit": commit_info.get("canonical_url"),
                        "function_names": ";".join(str(row.get("function_name") or "") for row in rows),
                        "cwes": ";".join(rows[0].get("_cwes", [])),
                        "reason": "download_or_parse_error",
                        "details": str(exc),
                        "top_candidates": "",
                    }
                )
            continue

        for group_key, rows in commit_groups:
            best, reason, candidates = choose_candidate(rows, files)
            if best is None:
                stats[reason] += 1
                unresolved.append(
                    {
                        "file_change_id": rows[0].get("file_change_id"),
                        "commit": commit_info.get("canonical_url"),
                        "function_names": ";".join(str(row.get("function_name") or "") for row in rows),
                        "cwes": ";".join(rows[0].get("_cwes", [])),
                        "reason": reason,
                        "details": "",
                        "top_candidates": ";".join(
                            f"{candidate.path}|score={candidate.score}|del={candidate.deleted_hits}|add={candidate.added_hits}"
                            for candidate in candidates[:5]
                        ),
                    }
                )
                continue
            stats["resolved_groups"] += 1
            resolved.append(
                {
                    "file_change_id": rows[0].get("file_change_id"),
                    "commit": commit_info.get("canonical_url"),
                    "repository": commit_info.get("repository"),
                    "file_path": best.path,
                    "old_path": best.old_path,
                    "new_path": best.new_path,
                    "match_method": reason,
                    "confidence": "high",
                    "match_evidence": {
                        "score": best.score,
                        "deleted_line_hits": best.deleted_hits,
                        "added_line_hits": best.added_hits,
                        "context_line_hits": best.context_hits,
                        "function_name_hits": best.function_name_hits,
                    },
                    "function_names": sorted(
                        {str(row.get("function_name") or "") for row in rows if row.get("function_name")}
                    ),
                    "cwes": rows[0].get("_cwes", []),
                    "source_lines": [row["_source_line"] for row in rows],
                }
            )

    resolved.sort(key=lambda row: (str(row["commit"]), str(row["file_change_id"])))
    unresolved.sort(key=lambda row: (str(row["commit"]), str(row["file_change_id"])))
    atomic_write_jsonl(args.output, resolved)
    write_csv(
        args.report_dir / "unresolved_file_paths.csv",
        ["file_change_id", "commit", "function_names", "cwes", "reason", "details", "top_candidates"],
        unresolved,
    )
    summary_rows = [{"metric": key, "value": value} for key, value in sorted(stats.items())]
    summary_rows.extend(
        [
            {"metric": "resolved_output_rows", "value": len(resolved)},
            {"metric": "unresolved_output_rows", "value": len(unresolved)},
        ]
    )
    write_csv(args.report_dir / "recovery_summary.csv", ["metric", "value"], summary_rows)
    return resolved, unresolved, stats


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Recover PyVul file_path metadata from fixing-commit diffs.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--function-dataset", type=Path, default=DEFAULT_FUNCTION_DATASET)
    parser.add_argument("--cwe-map", type=Path, default=DEFAULT_CWE_MAP)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_REPORT_DIR / "cache")
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--refresh", action="store_true", help="Redownload cached commit diffs")
    parser.add_argument(
        "--all-cwes",
        dest="target_only",
        action="store_false",
        help="Recover all CWE groups instead of the six project targets",
    )
    parser.add_argument(
        "--all-languages",
        dest="python_only",
        action="store_false",
        help="Recover all languages instead of Python metadata rows only",
    )
    parser.set_defaults(target_only=True, python_only=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.timeout <= 0 or args.retries < 0:
        print("error: timeout must be positive and retries cannot be negative", file=sys.stderr)
        return 2
    try:
        resolved, unresolved, stats = recover(args)
    except (RecoveryError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        f"Recovery complete: resolved={len(resolved)}, unresolved={len(unresolved)}, "
        f"commits={stats['selected_commits']}"
    )
    print(f"Metadata: {args.output.resolve()}")
    print(f"Reports:  {args.report_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
