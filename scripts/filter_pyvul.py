#!/usr/bin/env python3
"""Filter the PyVul function-level dataset using the project criteria.

The script is deliberately conservative: every input line is emitted to exactly
one of accepted.jsonl, manual_review.jsonl, or rejected.jsonl.  It never treats
an approximate token count as sufficient for ACCEPTED status.
"""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import io
import json
import os
import re
import sys
import tempfile
import textwrap
import tokenize
import warnings
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator, Mapping, Sequence


TARGETS: dict[str, tuple[str, str]] = {
    "CWE-22": ("PATH_TRAVERSAL", "A01"),
    "CWE-78": ("COMMAND_INJECTION", "A05"),
    "CWE-79": ("XSS", "A05"),
    "CWE-89": ("SQL_INJECTION", "A05"),
    "CWE-287": ("INSECURE_AUTHENTICATION", "A07"),
    "CWE-798": ("HARDCODED_CREDENTIALS", "A07"),
}
RELATED_CWES = {"CWE-23", "CWE-36", "CWE-77"}
REVIEW_PATH_PARTS = {"tests", "test", "docs", "examples", "vendor", "generated", "migrations"}
DEFAULT_MODEL = "microsoft/codebert-base"
DEFAULT_MAX_TOKENS = 512

STATUS_RANK = {"ACCEPTED": 0, "MANUAL_REVIEW": 1, "REJECTED": 2}
HEX_RE = re.compile(r"(?<![0-9a-f])([0-9a-f]{7,64})(?![0-9a-f])", re.IGNORECASE)
CWE_RE = re.compile(r"CWE[-_ ]?(\d+)", re.IGNORECASE)
GITHUB_RE = re.compile(r"github\.com/([^/]+)/([^/#?]+)", re.IGNORECASE)


class FilterError(RuntimeError):
    """Raised for a configuration or input error that prevents safe filtering."""


@dataclass(frozen=True)
class TokenCount:
    count: int
    exact: bool
    method: str


class TokenCounter:
    """CodeBERT token counter with an explicitly unsafe smoke-test fallback."""

    def __init__(
        self,
        model_name: str,
        *,
        offline: bool = False,
        allow_approximate: bool = False,
    ) -> None:
        self.model_name = model_name
        self._tokenizer: Any | None = None
        try:
            from transformers import AutoTokenizer  # type: ignore

            self._tokenizer = AutoTokenizer.from_pretrained(
                model_name,
                local_files_only=offline,
                use_fast=True,
            )
        except Exception as exc:
            if not allow_approximate:
                raise FilterError(
                    f"Cannot load the required tokenizer {model_name!r}: {exc}. "
                    "Install requirements-filter.txt and make the model available, or use "
                    "--allow-approximate-token-count only for a smoke test."
                ) from exc

    def count(self, code: str) -> TokenCount:
        if self._tokenizer is not None:
            ids = self._tokenizer.encode(code, add_special_tokens=True, truncation=False)
            return TokenCount(len(ids), True, self.model_name)
        # This estimate is never allowed into ACCEPTED output.
        pieces = re.findall(r"\w+|[^\w\s]", code, flags=re.UNICODE)
        return TokenCount(len(pieces) + 2, False, "approximate_regex_smoke_test")


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="surrogatepass")).hexdigest()


def normalize_cwes(value: Any) -> list[str]:
    if value is None:
        return []
    values: Iterable[Any] = value if isinstance(value, (list, tuple, set)) else [value]
    found: set[str] = set()
    for item in values:
        if item is None:
            continue
        for number in CWE_RE.findall(str(item)):
            found.add(f"CWE-{int(number)}")
    return sorted(found, key=lambda item: int(item.split("-", 1)[1]))


def normalize_commit(value: Any) -> dict[str, str | None]:
    raw = str(value or "").strip()
    repo_match = GITHUB_RE.search(raw)
    repository = None
    if repo_match:
        repository = f"{repo_match.group(1)}/{repo_match.group(2).removesuffix('.git')}"

    # Prefer hashes following /commit/ or /commits/, then the last hash-like token.
    preferred = re.findall(r"/(?:commit|commits)/([0-9a-f]{7,64})(?:[/?#]|$)", raw, re.IGNORECASE)
    candidates = preferred or HEX_RE.findall(raw)
    commit_id = candidates[-1].lower() if candidates else None
    canonical_url = (
        f"https://github.com/{repository}/commit/{commit_id}"
        if repository and commit_id
        else raw or None
    )
    return {
        "raw": raw or None,
        "repository": repository,
        "repository_id": repository.lower() if repository else None,
        "commit_id": commit_id,
        "canonical_url": canonical_url,
        "join_key": f"{repository.lower()}@{commit_id}" if repository and commit_id else raw or None,
    }


def clean_file_path(value: Any) -> str | None:
    if value is None:
        return None
    result = str(value).strip().replace("\\", "/")
    while result.startswith("./"):
        result = result[2:]
    return result or None


def record_file_path(record: Mapping[str, Any], enrichment: Mapping[str, Mapping[str, Any]]) -> str | None:
    for key in ("file_path", "filename", "old_path", "new_path"):
        path = clean_file_path(record.get(key))
        if path:
            return path
    file_change_id = str(record.get("file_change_id") or "")
    extra = enrichment.get(file_change_id, {})
    for key in ("file_path", "filename", "old_path", "new_path"):
        path = clean_file_path(extra.get(key))
        if path:
            return path
    return None


def is_review_path(path: str | None) -> bool:
    if not path:
        return False
    pure = PurePosixPath(path.lower())
    parts = set(pure.parts)
    name = pure.name
    return bool(
        parts & REVIEW_PATH_PARTS
        or name.startswith("test_")
        or name.endswith("_test.py")
    )


def has_binary_controls(code: str) -> bool:
    return "\x00" in code or any(ord(ch) < 9 or 13 < ord(ch) < 32 for ch in code)


def parse_python_unit(code: str) -> tuple[bool, bool, str | None, str]:
    """Return AST validity, presence of a function, error, and dedented code."""
    dedented = textwrap.dedent(code)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(dedented)
    except (SyntaxError, ValueError, TypeError) as exc:
        return False, False, f"{type(exc).__name__}: {exc}", dedented
    has_function = any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) for node in ast.walk(tree))
    return True, has_function, None, dedented


def normalized_python_code(code: str) -> str:
    """Remove comments and layout while preserving lexical tokens."""
    dedented = textwrap.dedent(code)
    try:
        tokens: list[str] = []
        for token in tokenize.generate_tokens(io.StringIO(dedented).readline):
            if token.type in {
                tokenize.ENCODING,
                tokenize.ENDMARKER,
                tokenize.INDENT,
                tokenize.DEDENT,
                tokenize.NEWLINE,
                tokenize.NL,
                tokenize.COMMENT,
            }:
                continue
            tokens.append(f"{token.type}:{token.string}")
        return "\n".join(tokens)
    except (tokenize.TokenError, IndentationError, SyntaxError):
        without_comments = re.sub(r"(?m)#.*$", "", dedented)
        return " ".join(without_comments.split())


def set_status(record: dict[str, Any], status: str, reason: str) -> None:
    if STATUS_RANK[status] > STATUS_RANK[record["status"]]:
        record["status"] = status
    if reason not in record["reason_codes"]:
        record["reason_codes"].append(reason)


def read_jsonl(path: Path) -> Iterator[tuple[int, dict[str, Any] | None, str | None]]:
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("JSON value is not an object")
                yield line_number, value, None
            except (json.JSONDecodeError, ValueError) as exc:
                yield line_number, None, f"{type(exc).__name__}: {exc}"


def load_enrichment(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    result: dict[str, dict[str, Any]] = {}
    for line_number, item, error in read_jsonl(path):
        if error or item is None:
            raise FilterError(f"Invalid enrichment JSONL at line {line_number}: {error}")
        key = str(item.get("file_change_id") or "")
        if not key:
            raise FilterError(f"Enrichment line {line_number} has no file_change_id")
        result[key] = item
    return result


def load_cwe_map(path: Path) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FilterError(f"Cannot read CWE map {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise FilterError(f"CWE map {path} must be a JSON object")
    by_raw: dict[str, set[str]] = defaultdict(set)
    by_join_key: dict[str, set[str]] = defaultdict(set)
    for commit, value in raw.items():
        cwes = normalize_cwes(value)
        by_raw[str(commit)].update(cwes)
        join_key = normalize_commit(commit)["join_key"]
        if join_key:
            by_join_key[str(join_key)].update(cwes)
        commit_id = normalize_commit(commit)["commit_id"]
        if commit_id:
            by_join_key[f"sha:{commit_id}"].update(cwes)
    return dict(by_raw), dict(by_join_key)


def load_commit_index(path: Path) -> tuple[set[str], set[str]]:
    raw_values: set[str] = set()
    join_keys: set[str] = set()
    with path.open("r", encoding="utf-8-sig") as handle:
        for line in handle:
            value = line.strip()
            if not value:
                continue
            raw_values.add(value)
            key = normalize_commit(value)["join_key"]
            if key:
                join_keys.add(str(key))
            commit_id = normalize_commit(value)["commit_id"]
            if commit_id:
                join_keys.add(f"sha:{commit_id}")
    return raw_values, join_keys


def source_cwes(record: Mapping[str, Any]) -> set[str]:
    values: list[Any] = []
    for key in ("cwe", "cwes", "CWE", "cwe_id"):
        if key in record:
            values.append(record.get(key))
    return {cwe for value in values for cwe in normalize_cwes(value)}


def language_decision(
    metadata: Any,
    file_path: str | None,
    ast_valid: bool,
) -> tuple[bool, bool, bool]:
    """Return (is_python, metadata/path conflict, language_unknown)."""
    language = str(metadata or "").strip().lower()
    metadata_known = bool(language and language not in {"unknown", "none", "null"})
    metadata_python = language in {"python", "py", "python3"}
    suffix = PurePosixPath(file_path).suffix.lower() if file_path else ""
    path_known = bool(suffix)
    path_python = suffix == ".py"
    conflict = metadata_known and path_known and metadata_python != path_python
    if conflict:
        return metadata_python or path_python, True, False
    if metadata_known:
        return metadata_python, False, False
    if path_known:
        return path_python, False, False
    return ast_valid, False, not ast_valid


def build_record(
    raw: Mapping[str, Any],
    *,
    raw_index: int,
    cwe_by_raw: Mapping[str, set[str]],
    cwe_by_join_key: Mapping[str, set[str]],
    commit_raw: set[str],
    commit_join_keys: set[str],
    enrichment: Mapping[str, Mapping[str, Any]],
    token_counter: TokenCounter,
    max_tokens: int,
) -> dict[str, Any]:
    commit_info = normalize_commit(raw.get("commit") or raw.get("commit_url") or raw.get("commit_hash"))
    if not commit_info["repository"] and raw.get("repository"):
        repository = str(raw["repository"]).strip().removesuffix(".git").rstrip("/")
        repository = re.sub(r"^https?://github\.com/", "", repository, flags=re.IGNORECASE)
        if repository:
            commit_info["repository"] = repository
            commit_info["repository_id"] = repository.lower()
            if commit_info["commit_id"]:
                commit_info["canonical_url"] = f"https://github.com/{repository}/commit/{commit_info['commit_id']}"
                commit_info["join_key"] = f"{repository.lower()}@{commit_info['commit_id']}"
    raw_commit = str(commit_info["raw"] or "")
    join_key = str(commit_info["join_key"] or "")
    sha_key = f"sha:{commit_info['commit_id']}" if commit_info["commit_id"] else ""
    mapped_cwes = (
        set(cwe_by_raw.get(raw_commit, set()))
        | set(cwe_by_join_key.get(join_key, set()))
        | set(cwe_by_join_key.get(sha_key, set()))
    )
    embedded_cwes = source_cwes(raw)
    all_cwes = sorted(mapped_cwes | embedded_cwes, key=lambda item: int(item.split("-")[1]))
    target_cwes = [item for item in all_cwes if item in TARGETS]
    related_cwes = [item for item in all_cwes if item in RELATED_CWES]

    code_before_value = raw.get("code_before")
    code_before = code_before_value if isinstance(code_before_value, str) else ""
    code_after_value = raw.get("code_after")
    code_after = code_after_value if isinstance(code_after_value, str) else ""
    function_name = str(raw.get("function_name") or raw.get("method_name") or "").strip() or None
    file_path = record_file_path(raw, enrichment)

    ast_valid_before, has_function_before, ast_error_before, _ = parse_python_unit(code_before)
    ast_valid_after, has_function_after, ast_error_after, _ = (
        parse_python_unit(code_after) if code_after.strip() else (False, False, None, "")
    )
    is_python, language_conflict, language_unknown = language_decision(
        raw.get("programming_language"), file_path, ast_valid_before
    )

    exact_hash = sha256_text(code_before) if code_before else None
    normalized_before = normalized_python_code(code_before) if code_before else ""
    normalized_hash = sha256_text(normalized_before) if normalized_before else None
    exact_after_hash = sha256_text(code_after) if code_after else None
    normalized_after = normalized_python_code(code_after) if code_after else ""

    file_identity = file_path or (f"file_change_id:{raw.get('file_change_id')}" if raw.get("file_change_id") else "")
    pair_material = "|".join(
        str(value or "")
        for value in (
            commit_info["repository_id"],
            commit_info["commit_id"],
            file_identity,
            function_name,
        )
    )
    pair_id = sha256_text(pair_material) if pair_material.strip("|") else None

    record: dict[str, Any] = {
        "sample_id": None,
        "source_dataset": "PyVul",
        "source_line": raw_index,
        "repository": commit_info["repository"],
        "repository_id": commit_info["repository_id"],
        "commit": commit_info["commit_id"],
        "commit_url": commit_info["canonical_url"],
        "commit_id": commit_info["commit_id"],
        "file_path": file_path,
        "file_change_id": raw.get("file_change_id"),
        "function_name": function_name,
        "language": "Python" if is_python else raw.get("programming_language"),
        "cwes": all_cwes,
        "labels": [TARGETS[cwe][0] for cwe in target_cwes],
        "owasp_2025": sorted({TARGETS[cwe][1] for cwe in target_cwes}),
        "is_multi_label": len(target_cwes) > 1,
        "code_before": code_before,
        "code_after": code_after or None,
        "has_paired_negative": bool(code_after.strip()),
        "pair_id": pair_id,
        "exact_code_hash": exact_hash,
        "normalized_code_hash": normalized_hash,
        "exact_code_after_hash": exact_after_hash,
        "token_count_before": None,
        "token_count_after": None,
        "tokenizer": token_counter.model_name,
        "token_count_method": None,
        "exceeds_model_limit": False,
        "model_token_limit": max_tokens,
        "ast_valid_before": ast_valid_before,
        "ast_valid_after": ast_valid_after if code_after.strip() else None,
        "ast_error_before": ast_error_before,
        "ast_error_after": ast_error_after,
        "commit_message": raw.get("commit_message"),
        "report_link": raw.get("report_link"),
        "description": raw.get("description"),
        "status": "ACCEPTED",
        "reason_codes": [],
        "is_duplicate": False,
        "duplicate_of": None,
        "duplicate_sources": [],
    }

    if embedded_cwes and mapped_cwes and embedded_cwes != mapped_cwes:
        set_status(record, "MANUAL_REVIEW", "manual_review_label_conflict")
    if not all_cwes:
        set_status(record, "REJECTED", "rejected_missing_cwe")
    elif not target_cwes:
        if related_cwes:
            set_status(record, "MANUAL_REVIEW", "manual_review_related_cwe")
        else:
            set_status(record, "REJECTED", "rejected_non_target_cwe")
    elif len(target_cwes) > 1:
        set_status(record, "MANUAL_REVIEW", "manual_review_multiple_cwes")

    if code_before_value is None:
        set_status(record, "REJECTED", "rejected_missing_vulnerable_code")
    elif not isinstance(code_before_value, str) or not code_before.strip():
        set_status(record, "REJECTED", "rejected_empty_code")
    elif has_binary_controls(code_before):
        set_status(record, "REJECTED", "rejected_binary_code")

    if language_conflict:
        set_status(record, "MANUAL_REVIEW", "manual_review_language_conflict")
    elif language_unknown:
        set_status(record, "MANUAL_REVIEW", "manual_review_language_unknown")
    elif not is_python:
        set_status(record, "REJECTED", "rejected_non_python")

    if is_python and code_before.strip():
        if not ast_valid_before:
            set_status(record, "MANUAL_REVIEW", "manual_review_ast_error")
        elif not has_function_before:
            set_status(record, "MANUAL_REVIEW", "manual_review_missing_context")
    if is_python and code_after.strip():
        if not ast_valid_after:
            set_status(record, "MANUAL_REVIEW", "manual_review_ast_error")
        elif not has_function_after:
            set_status(record, "MANUAL_REVIEW", "manual_review_missing_context")

    if not function_name:
        set_status(record, "REJECTED", "rejected_missing_function_identifier")
    if not commit_info["repository"] or not commit_info["commit_id"]:
        set_status(record, "MANUAL_REVIEW", "manual_review_missing_provenance")
    if not file_path:
        set_status(record, "MANUAL_REVIEW", "manual_review_missing_provenance")
    if raw_commit and raw_commit not in commit_raw and join_key not in commit_join_keys and sha_key not in commit_join_keys:
        set_status(record, "MANUAL_REVIEW", "manual_review_commit_not_in_pyvul")
    if is_review_path(file_path):
        set_status(record, "MANUAL_REVIEW", "manual_review_test_or_generated_code")

    if code_before and code_after:
        if code_before == code_after:
            set_status(record, "REJECTED", "rejected_unchanged_pair")
        elif normalized_before and normalized_before == normalized_after:
            set_status(record, "MANUAL_REVIEW", "manual_review_nonsemantic_change")

    if code_before:
        before_count = token_counter.count(code_before)
        record["token_count_before"] = before_count.count
        record["token_count_method"] = before_count.method
        if not before_count.exact:
            set_status(record, "MANUAL_REVIEW", "manual_review_tokenizer_unavailable")
        if before_count.count > max_tokens:
            record["exceeds_model_limit"] = True
            set_status(record, "MANUAL_REVIEW", "manual_review_long_code")
    if code_after:
        after_count = token_counter.count(code_after)
        record["token_count_after"] = after_count.count
        if not after_count.exact:
            set_status(record, "MANUAL_REVIEW", "manual_review_tokenizer_unavailable")
        if after_count.count > max_tokens:
            record["exceeds_model_limit"] = True
            set_status(record, "MANUAL_REVIEW", "manual_review_long_code")

    return record


def malformed_record(line_number: int, error: str) -> dict[str, Any]:
    return {
        "sample_id": f"PYVUL_INVALID_{line_number:06d}",
        "source_dataset": "PyVul",
        "source_line": line_number,
        "repository": None,
        "repository_id": None,
        "commit": None,
        "commit_url": None,
        "commit_id": None,
        "file_path": None,
        "file_change_id": None,
        "function_name": None,
        "language": None,
        "cwes": [],
        "labels": [],
        "owasp_2025": [],
        "is_multi_label": False,
        "code_before": None,
        "code_after": None,
        "has_paired_negative": False,
        "pair_id": None,
        "exact_code_hash": None,
        "normalized_code_hash": None,
        "exact_code_after_hash": None,
        "token_count_before": None,
        "token_count_after": None,
        "tokenizer": None,
        "token_count_method": None,
        "exceeds_model_limit": False,
        "model_token_limit": None,
        "ast_valid_before": False,
        "ast_valid_after": None,
        "ast_error_before": error,
        "ast_error_after": None,
        "commit_message": None,
        "report_link": None,
        "description": None,
        "status": "REJECTED",
        "reason_codes": ["rejected_invalid_json"],
        "is_duplicate": False,
        "duplicate_of": None,
        "duplicate_sources": [],
    }


def assign_sample_ids(records: Sequence[dict[str, Any]]) -> None:
    counters: Counter[str] = Counter()
    for record in records:
        cwe = next((item for item in record["cwes"] if item in TARGETS), None)
        bucket = cwe.replace("-", "") if cwe else "UNMAPPED"
        counters[bucket] += 1
        if not str(record.get("sample_id") or "").startswith("PYVUL_INVALID_"):
            record["sample_id"] = f"PYVUL_{bucket}_{counters[bucket]:06d}"


def resolve_duplicates(records: Sequence[dict[str, Any]]) -> None:
    """Mark duplicates while retaining provenance on a deterministic primary."""
    parents = list(range(len(records)))

    def find(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    def union(left: int, right: int) -> None:
        left_root, right_root = find(left), find(right)
        if left_root != right_root:
            parents[right_root] = left_root

    first_by_key: dict[tuple[str, str], int] = {}
    for index, record in enumerate(records):
        for kind, raw_key in (
            ("code", record.get("normalized_code_hash") or record.get("exact_code_hash")),
            ("identity", record.get("pair_id")),
        ):
            if not raw_key:
                continue
            key = (kind, str(raw_key))
            if key in first_by_key:
                union(first_by_key[key], index)
            else:
                first_by_key[key] = index

    components: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for index, record in enumerate(records):
        components[find(index)].append(record)

    for items in components.values():
        if len(items) < 2:
            continue
        primary = min(items, key=lambda item: int(item["source_line"]))
        provenance = [
            {
                "sample_id": item["sample_id"],
                "source_line": item["source_line"],
                "repository": item["repository"],
                "commit": item["commit"],
                "file_path": item["file_path"],
                "report_link": item["report_link"],
            }
            for item in items
            if item is not primary
        ]
        primary["duplicate_sources"] = provenance
        for duplicate in items:
            if duplicate is primary:
                continue
            duplicate["is_duplicate"] = True
            duplicate["duplicate_of"] = primary["sample_id"]

        label_sets = {tuple(sorted(item["cwes"])) for item in items}
        if len(label_sets) > 1:
            for item in items:
                set_status(item, "MANUAL_REVIEW", "manual_review_label_conflict")
            continue

        for duplicate in items:
            if duplicate is primary:
                continue
            set_status(duplicate, "REJECTED", "rejected_duplicate")


def finalize_reasons(records: Sequence[dict[str, Any]]) -> None:
    for record in records:
        if record["status"] == "ACCEPTED":
            record["reason_codes"] = ["accepted_exact_target_cwe"]
        elif not record["reason_codes"]:
            record["reason_codes"] = ["manual_review_unspecified"]
            record["status"] = "MANUAL_REVIEW"


SUMMARY_COLUMNS = [
    "cwe",
    "label",
    "owasp_2025",
    "total_raw",
    "python_samples",
    "accepted",
    "manual_review",
    "rejected",
    "unique_repositories",
    "unique_commits",
    "vulnerable_fixed_pairs",
    "duplicates",
    "over_token_limit",
]


def summary_rows(records: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for cwe, (label, owasp) in TARGETS.items():
        items = [record for record in records if cwe in record["cwes"]]
        rows.append(
            {
                "cwe": cwe,
                "label": label,
                "owasp_2025": owasp,
                "total_raw": len(items),
                "python_samples": sum(record["language"] == "Python" for record in items),
                "accepted": sum(record["status"] == "ACCEPTED" for record in items),
                "manual_review": sum(record["status"] == "MANUAL_REVIEW" for record in items),
                "rejected": sum(record["status"] == "REJECTED" for record in items),
                "unique_repositories": len({record["repository_id"] for record in items if record["repository_id"]}),
                "unique_commits": len({record["commit_id"] for record in items if record["commit_id"]}),
                "vulnerable_fixed_pairs": len(
                    {record["pair_id"] for record in items if record["has_paired_negative"] and record["pair_id"]}
                ),
                "duplicates": sum(record["is_duplicate"] for record in items),
                "over_token_limit": sum(record["exceeds_model_limit"] for record in items),
            }
        )
    return rows


def write_outputs(records: Sequence[dict[str, Any]], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    temp_dir = Path(tempfile.mkdtemp(prefix=".pyvul-filter-", dir=output_dir))
    try:
        for status, filename in (
            ("ACCEPTED", "accepted.jsonl"),
            ("MANUAL_REVIEW", "manual_review.jsonl"),
            ("REJECTED", "rejected.jsonl"),
        ):
            with (temp_dir / filename).open("w", encoding="utf-8", newline="\n") as handle:
                for record in records:
                    if record["status"] == status:
                        handle.write(json.dumps(record, ensure_ascii=False, sort_keys=False) + "\n")

        with (temp_dir / "filter_summary.csv").open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=SUMMARY_COLUMNS)
            writer.writeheader()
            writer.writerows(summary_rows(records))

        for filename in ("accepted.jsonl", "manual_review.jsonl", "rejected.jsonl", "filter_summary.csv"):
            os.replace(temp_dir / filename, output_dir / filename)
    finally:
        try:
            temp_dir.rmdir()
        except OSError:
            pass


def filter_dataset(args: argparse.Namespace) -> list[dict[str, Any]]:
    for path in (args.function_dataset, args.cwe_map, args.commit_dataset):
        if not path.is_file():
            raise FilterError(f"Required input file does not exist: {path}")
    if args.max_tokens <= 0:
        raise FilterError("--max-tokens must be greater than zero")

    cwe_by_raw, cwe_by_join_key = load_cwe_map(args.cwe_map)
    commit_raw, commit_join_keys = load_commit_index(args.commit_dataset)
    enrichment = load_enrichment(args.file_metadata)
    token_counter = TokenCounter(
        args.tokenizer,
        offline=args.offline,
        allow_approximate=args.allow_approximate_token_count,
    )

    records: list[dict[str, Any]] = []
    for line_number, raw, error in read_jsonl(args.function_dataset):
        if raw is None:
            records.append(malformed_record(line_number, error or "Unknown JSON error"))
            continue
        records.append(
            build_record(
                raw,
                raw_index=line_number,
                cwe_by_raw=cwe_by_raw,
                cwe_by_join_key=cwe_by_join_key,
                commit_raw=commit_raw,
                commit_join_keys=commit_join_keys,
                enrichment=enrichment,
                token_counter=token_counter,
                max_tokens=args.max_tokens,
            )
        )

    assign_sample_ids(records)
    resolve_duplicates(records)
    finalize_reasons(records)
    write_outputs(records, args.output_dir)
    return records


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description="Filter PyVul into accepted/manual-review/rejected JSONL files.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    result.add_argument("--function-dataset", type=Path, default=Path("dataset/function_level_dataset.out"))
    result.add_argument("--cwe-map", type=Path, default=Path("dataset/commits_cwe_map.json"))
    result.add_argument("--commit-dataset", type=Path, default=Path("dataset/commit_level_dataset.out"))
    result.add_argument("--output-dir", type=Path, default=Path("data/processed"))
    result.add_argument(
        "--file-metadata",
        type=Path,
        default=None,
        help="Optional JSONL containing file_change_id and file_path/old_path/new_path",
    )
    result.add_argument("--tokenizer", default=DEFAULT_MODEL)
    result.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS)
    result.add_argument("--offline", action="store_true", help="Do not download tokenizer files")
    result.add_argument(
        "--allow-approximate-token-count",
        action="store_true",
        help="Smoke tests only; approximate counts force otherwise valid rows to MANUAL_REVIEW",
    )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        records = filter_dataset(args)
    except (FilterError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    counts = Counter(record["status"] for record in records)
    print(
        f"Processed {len(records)} records: "
        f"ACCEPTED={counts['ACCEPTED']}, "
        f"MANUAL_REVIEW={counts['MANUAL_REVIEW']}, "
        f"REJECTED={counts['REJECTED']}"
    )
    print(f"Wrote outputs to {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
