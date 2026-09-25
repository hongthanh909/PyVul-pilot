#!/usr/bin/env python3
"""Validate normalized external function pairs with the shared project rules."""

from __future__ import annotations

import argparse
import ast
import csv
import json
import re
import tempfile
import textwrap
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping

try:  # direct script execution adds scripts/ to sys.path
    from filter_pyvul import (
        DEFAULT_MAX_TOKENS,
        DEFAULT_MODEL,
        TARGETS,
        TokenCounter,
        is_review_path,
        normalized_python_code,
        parse_python_unit,
        sha256_text,
    )
except ModuleNotFoundError:  # imported as scripts.filter_normalized_pairs in tests
    from scripts.filter_pyvul import (
        DEFAULT_MAX_TOKENS,
        DEFAULT_MODEL,
        TARGETS,
        TokenCounter,
        is_review_path,
        normalized_python_code,
        parse_python_unit,
        sha256_text,
    )


REQUIRED = {
    "schema_version",
    "sample_id",
    "source_dataset",
    "source_dataset_url",
    "source_record_id",
    "repository",
    "commit_id",
    "commit_url",
    "file_path",
    "function_name",
    "language",
    "cwes",
    "code_before",
    "code_after",
}
STATUS_RANK = {"ACCEPTED": 0, "MANUAL_REVIEW": 1, "REJECTED": 2}
CREDENTIAL_NAME_RE = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|access[_-]?token|jwt[_-]?key|signing[_-]?key|credential)",
    re.IGNORECASE,
)
PLACEHOLDER_RE = re.compile(r"^(?:none|null|changeme|change-me|example|dummy|test|mock)$", re.I)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row, dict):
                raise ValueError(f"Expected object at {path}:{line_number}")
            row["_input_line"] = line_number
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


def set_status(record: dict[str, Any], status: str, reason: str) -> None:
    if STATUS_RANK[status] > STATUS_RANK[record["status"]]:
        record["status"] = status
    if reason not in record["reason_codes"]:
        record["reason_codes"].append(reason)


def target_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{target_name(node.value)}.{node.attr}".strip(".")
    if isinstance(node, ast.Subscript):
        suffix = ""
        if isinstance(node.slice, ast.Constant):
            suffix = str(node.slice.value)
        return f"{target_name(node.value)}.{suffix}".strip(".")
    if isinstance(node, (ast.Tuple, ast.List)):
        return ".".join(target_name(item) for item in node.elts)
    return ""


def hardcoded_credentials(code: str) -> set[tuple[str, str]]:
    """Find credential literals, including unsafe environment fallback values."""
    result: set[tuple[str, str]] = set()
    try:
        tree = ast.parse(textwrap.dedent(code))
    except SyntaxError:
        return result
    # Resolve only literal top-level aliases. This catches
    # JWT_SECRET = os.environ.get("...", _DEFAULT_SECRET) without executing code.
    literal_aliases: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        else:
            continue
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            for target in targets:
                if isinstance(target, ast.Name):
                    literal_aliases[target.id] = value.value
    for node in ast.walk(tree):
        targets: list[ast.AST] = []
        value: ast.AST | None = None
        if isinstance(node, ast.Assign):
            targets, value = list(node.targets), node.value
        elif isinstance(node, ast.AnnAssign):
            targets, value = [node.target], node.value
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "get"
            and isinstance(value.func.value, ast.Attribute)
            and isinstance(value.func.value.value, ast.Name)
            and value.func.value.value.id == "os"
            and value.func.value.attr == "environ"
            and len(value.args) >= 2
        ):
            value = value.args[1]
        if isinstance(value, ast.Name) and value.id in literal_aliases:
            value = ast.Constant(value=literal_aliases[value.id])
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            continue
        literal = value.value.strip()
        if len(literal) < 3 or PLACEHOLDER_RE.match(literal):
            continue
        for target in targets:
            name = target_name(target)
            if CREDENTIAL_NAME_RE.search(name):
                result.add((name.lower(), literal))
    return result


def has_top_level_binding(code: str, binding: str) -> bool:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return False
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        if any(isinstance(target, ast.Name) and target.id == binding for target in targets):
            return True
    return False


def build_record(raw: Mapping[str, Any], token_counter: Any, max_tokens: int) -> dict[str, Any]:
    before = raw.get("code_before") if isinstance(raw.get("code_before"), str) else ""
    after = raw.get("code_after") if isinstance(raw.get("code_after"), str) else ""
    cwes = sorted({str(value) for value in raw.get("cwes") or []})
    target_cwes = [cwe for cwe in cwes if cwe in TARGETS]
    before_valid, before_function, before_error, _ = parse_python_unit(before)
    after_valid, after_function, after_error, _ = parse_python_unit(after)
    before_normalized = normalized_python_code(before) if before else ""
    after_normalized = normalized_python_code(after) if after else ""
    pair_material = "|".join(
        str(raw.get(key) or "")
        for key in ("repository", "commit_id", "file_path", "function_name")
    )
    before_count = token_counter.count(before) if before else None
    after_count = token_counter.count(after) if after else None
    record = dict(raw)
    record.pop("_input_line", None)
    record.update(
        {
            "source_line": raw.get("_input_line"),
            "repository_id": str(raw.get("repository") or "").lower() or None,
            "commit": raw.get("commit_id"),
            "labels": [TARGETS[cwe][0] for cwe in target_cwes],
            "owasp_2025": sorted({TARGETS[cwe][1] for cwe in target_cwes}),
            "is_multi_label": len(target_cwes) > 1,
            "has_paired_negative": bool(after.strip()),
            "pair_id": sha256_text(pair_material),
            "exact_code_hash": sha256_text(before) if before else None,
            "normalized_code_hash": sha256_text(before_normalized) if before_normalized else None,
            "exact_code_after_hash": sha256_text(after) if after else None,
            "token_count_before": before_count.count if before_count else None,
            "token_count_after": after_count.count if after_count else None,
            "tokenizer": token_counter.model_name,
            "token_count_method": before_count.method if before_count else None,
            "exceeds_model_limit": bool(
                (before_count and before_count.count > max_tokens)
                or (after_count and after_count.count > max_tokens)
            ),
            "model_token_limit": max_tokens,
            "ast_valid_before": before_valid,
            "ast_valid_after": after_valid,
            "ast_error_before": before_error,
            "ast_error_after": after_error,
            "report_link": raw.get("advisory_url"),
            "status": "ACCEPTED",
            "reason_codes": [],
            "is_duplicate": False,
            "duplicate_of": None,
            "duplicate_sources": [],
        }
    )

    missing = sorted(key for key in REQUIRED if raw.get(key) in (None, "", []))
    if missing:
        set_status(record, "REJECTED", "rejected_schema_required_field_missing")
        record["missing_required_fields"] = missing
    if raw.get("schema_version") != "1.0":
        set_status(record, "REJECTED", "rejected_schema_version")
    if raw.get("language") != "Python" or not str(raw.get("file_path") or "").endswith(".py"):
        set_status(record, "REJECTED", "rejected_non_python")
    if len(target_cwes) != 1 or len(cwes) != 1:
        set_status(record, "MANUAL_REVIEW", "manual_review_non_exact_target_cwe")
    advisory_cwes = sorted({str(value) for value in raw.get("advisory_cwes") or cwes})
    if len(advisory_cwes) > 1 and not (
        cwes == ["CWE-798"]
        and "CWE-798" in advisory_cwes
        and raw.get("unit_type") == "module_block"
        and str(raw.get("cwe_isolation_evidence") or "").strip()
    ):
        set_status(record, "MANUAL_REVIEW", "manual_review_multi_cwe_without_isolation_evidence")
    if not before_valid or not after_valid:
        set_status(record, "MANUAL_REVIEW", "manual_review_ast_error")
    elif raw.get("unit_type", "function") == "module_block":
        binding = str(raw.get("function_name") or "").removeprefix("module:")
        if cwes != ["CWE-798"] or not str(raw.get("function_name") or "").startswith("module:"):
            set_status(record, "MANUAL_REVIEW", "manual_review_invalid_module_scope")
        elif not has_top_level_binding(before, binding) or not has_top_level_binding(after, binding):
            set_status(record, "MANUAL_REVIEW", "manual_review_missing_module_binding")
        elif not all(isinstance(raw.get(key), int) and raw[key] > 0 for key in (
            "start_line_before", "end_line_before", "start_line_after", "end_line_after"
        )):
            set_status(record, "MANUAL_REVIEW", "manual_review_missing_source_lines")
    elif raw.get("unit_type", "function") != "function" or not before_function or not after_function:
        set_status(record, "MANUAL_REVIEW", "manual_review_missing_function_context")
    if before == after:
        set_status(record, "REJECTED", "rejected_unchanged_pair")
    elif before_normalized == after_normalized:
        set_status(record, "MANUAL_REVIEW", "manual_review_nonsemantic_change")
    if is_review_path(str(raw.get("file_path") or "")):
        set_status(record, "MANUAL_REVIEW", "manual_review_test_or_generated_code")
    if before_count and not before_count.exact or after_count and not after_count.exact:
        set_status(record, "MANUAL_REVIEW", "manual_review_tokenizer_unavailable")

    # Exact CWE-798 on an advisory is necessary but not enough: a multi-change
    # commit can touch functions unrelated to the credential. Automatic
    # acceptance therefore requires a literal credential assignment in the
    # vulnerable function that disappears or changes in the fixed function.
    if cwes == ["CWE-798"]:
        vulnerable_literals = hardcoded_credentials(before)
        fixed_literals = hardcoded_credentials(after)
        if raw.get("unit_type") == "module_block":
            binding_name = str(raw.get("function_name") or "").removeprefix("module:").lower()
            vulnerable_literals = {item for item in vulnerable_literals if item[0] == binding_name}
            fixed_literals = {item for item in fixed_literals if item[0] == binding_name}
        removed = vulnerable_literals - fixed_literals
        record["cwe798_hardcoded_credentials_before"] = sorted(vulnerable_literals)
        record["cwe798_hardcoded_credentials_after"] = sorted(fixed_literals)
        record["cwe798_removed_credentials"] = sorted(removed)
        if not removed:
            set_status(record, "MANUAL_REVIEW", "manual_review_cwe798_semantic_evidence")
        if fixed_literals:
            set_status(record, "MANUAL_REVIEW", "manual_review_cwe798_residual_hardcoded_credential")

    if record["exceeds_model_limit"]:
        set_status(record, "MANUAL_REVIEW", "manual_review_long_code")
    return record


def resolve_duplicates(records: list[dict[str, Any]]) -> None:
    first: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        key = ("|".join(sorted(record.get("cwes") or [])), str(record.get("normalized_code_hash") or ""))
        if not key[1]:
            continue
        primary = first.get(key)
        if primary is None:
            first[key] = record
            continue
        record["is_duplicate"] = True
        record["duplicate_of"] = primary.get("sample_id")
        primary["duplicate_sources"].append(
            {
                "sample_id": record.get("sample_id"),
                "repository": record.get("repository"),
                "commit_id": record.get("commit_id"),
                "file_path": record.get("file_path"),
            }
        )
        set_status(record, "REJECTED", "rejected_duplicate")


def finalize(records: list[dict[str, Any]]) -> None:
    for record in records:
        if record["status"] == "ACCEPTED":
            record["reason_codes"] = ["accepted_exact_target_cwe"]


def write_outputs(output_dir: Path, records: list[dict[str, Any]]) -> None:
    for status, filename in (
        ("ACCEPTED", "accepted.jsonl"),
        ("MANUAL_REVIEW", "manual_review.jsonl"),
        ("REJECTED", "rejected.jsonl"),
    ):
        atomic_jsonl(output_dir / filename, (row for row in records if row["status"] == status))
    counts = Counter(row["status"] for row in records)
    with (output_dir / "filter_summary.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["metric", "value"])
        writer.writeheader()
        writer.writerow({"metric": "input_function_pairs", "value": len(records)})
        for status in ("ACCEPTED", "MANUAL_REVIEW", "REJECTED"):
            writer.writerow({"metric": status, "value": counts[status]})
        writer.writerow(
            {"metric": "over_token_limit", "value": sum(row["exceeds_model_limit"] for row in records)}
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=Path("data/supplement/cwe-798/normalized_pairs.jsonl"))
    parser.add_argument("--output-dir", type=Path, default=Path("data/supplement/cwe-798/processed"))
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    counter = TokenCounter(args.model, offline=args.offline)
    records = [build_record(row, counter, args.max_tokens) for row in read_jsonl(args.input)]
    resolve_duplicates(records)
    finalize(records)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_outputs(args.output_dir, records)
    counts = Counter(row["status"] for row in records)
    print(f"Processed {len(records)} normalized pairs: " + ", ".join(f"{k}={counts[k]}" for k in ("ACCEPTED", "MANUAL_REVIEW", "REJECTED")))
    print(f"Wrote outputs to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
