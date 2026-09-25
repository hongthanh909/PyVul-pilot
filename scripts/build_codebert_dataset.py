#!/usr/bin/env python3
"""Build one canonical CodeBERT dataset from accepted pairs and long chunks."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
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


def digest(code: str) -> str:
    return hashlib.sha256(code.encode("utf-8", errors="surrogatepass")).hexdigest()


def full_function_samples(record: Mapping[str, Any]) -> list[dict[str, Any]]:
    parent = str(record.get("sample_id") or "")
    group = str(record.get("pair_id") or parent)
    common = {
        "model_schema_version": "1.0",
        "parent_sample_id": parent,
        "group_id": group,
        "source_dataset": record.get("source_dataset") or "unknown",
        "source_record_id": record.get("source_record_id"),
        "source_type": "module_block" if record.get("unit_type") == "module_block" else "full_function",
        "unit_type": record.get("unit_type") or "function",
        "repository": record.get("repository"),
        "commit_id": record.get("commit_id") or record.get("commit"),
        "commit_url": record.get("commit_url"),
        "file_path": record.get("file_path"),
        "function_name": record.get("function_name"),
        "start_line_before": record.get("start_line_before"),
        "end_line_before": record.get("end_line_before"),
        "start_line_after": record.get("start_line_after"),
        "end_line_after": record.get("end_line_after"),
        "source_spans_before": record.get("source_spans_before"),
        "source_spans_after": record.get("source_spans_after"),
        "cwes": record.get("cwes", []),
        "advisory_cwes": record.get("advisory_cwes"),
        "cwe_isolation_evidence": record.get("cwe_isolation_evidence"),
        "labels": record.get("labels", []),
        "tokenizer": record.get("tokenizer"),
        "platform": record.get("platform"),
        "vulnerability_scope": record.get("vulnerability_scope"),
        "domain": record.get("domain"),
        "curation_status": record.get("curation_status"),
        "curation_notes": record.get("curation_notes"),
    }
    result: list[dict[str, Any]] = []
    for variant, code_key, token_key, vulnerable in (
        ("before", "code_before", "token_count_before", True),
        ("after", "code_after", "token_count_after", False),
    ):
        code = record.get(code_key)
        token_count = record.get(token_key)
        if not isinstance(code, str) or not code.strip() or not isinstance(token_count, int):
            continue
        sample = {
            **common,
            "model_sample_id": f"{parent}:{variant}",
            "code": code,
            "variant": variant,
            "start_line": record.get(f"start_line_{variant}"),
            "end_line": record.get(f"end_line_{variant}"),
            "source_spans": record.get(f"source_spans_{variant}"),
            "is_vulnerable": vulnerable,
            "token_count": token_count,
            "code_sha256": digest(code),
        }
        result.append(sample)
    return result


def chunk_sample(record: Mapping[str, Any], fallback_source: str) -> dict[str, Any] | None:
    if not record.get("eligible_for_training") or record.get("chunk_status") != "MODEL_READY":
        return None
    code = record.get("chunk_code")
    if not isinstance(code, str) or not code.strip():
        return None
    variant = str(record.get("variant") or "")
    return {
        "model_schema_version": "1.0",
        "model_sample_id": str(record.get("chunk_id") or ""),
        "parent_sample_id": str(record.get("parent_sample_id") or ""),
        "group_id": str(record.get("pair_id") or record.get("parent_sample_id") or ""),
        "source_dataset": record.get("source_dataset") or fallback_source,
        "source_record_id": record.get("source_record_id"),
        "source_type": "long_chunk",
        "unit_type": record.get("unit_type") or "function",
        "repository": record.get("repository"),
        "commit_id": record.get("commit_id") or record.get("commit"),
        "commit_url": record.get("commit_url"),
        "file_path": record.get("file_path"),
        "function_name": record.get("function_name"),
        "start_line_before": record.get("start_line_before"),
        "end_line_before": record.get("end_line_before"),
        "start_line_after": record.get("start_line_after"),
        "end_line_after": record.get("end_line_after"),
        "code": code,
        "variant": variant,
        "is_vulnerable": bool(record.get("is_vulnerable_for_target_cwe")),
        "cwes": record.get("cwes", []),
        "advisory_cwes": record.get("advisory_cwes"),
        "cwe_isolation_evidence": record.get("cwe_isolation_evidence"),
        "labels": record.get("labels", []),
        "token_count": record.get("chunk_token_count"),
        "tokenizer": record.get("tokenizer"),
        "code_sha256": digest(code),
        "chunk_index": record.get("chunk_index"),
        "contains_patch": record.get("contains_patch"),
        "platform": record.get("platform"),
        "vulnerability_scope": record.get("vulnerability_scope"),
        "domain": record.get("domain"),
        "curation_status": record.get("curation_status"),
        "curation_notes": record.get("curation_notes"),
    }


def validate(sample: Mapping[str, Any], max_tokens: int = 512) -> list[str]:
    errors: list[str] = []
    required = (
        "model_sample_id",
        "parent_sample_id",
        "group_id",
        "source_dataset",
        "repository",
        "commit_id",
        "file_path",
        "function_name",
        "code",
        "cwes",
        "labels",
        "tokenizer",
    )
    errors.extend(f"missing_{key}" for key in required if sample.get(key) in (None, "", []))
    if sample.get("variant") not in {"before", "after"}:
        errors.append("invalid_variant")
    token_count = sample.get("token_count")
    if not isinstance(token_count, int) or not 1 <= token_count <= max_tokens:
        errors.append("invalid_token_count")
    if not str(sample.get("file_path") or "").endswith(".py"):
        errors.append("non_python_path")
    return errors


def deduplicate(
    samples: Sequence[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for sample in samples:
        groups[str(sample["code_sha256"])].append(sample)
    kept: list[dict[str, Any]] = []
    duplicates: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    for code_hash, items in groups.items():
        signatures = {
            (bool(item["is_vulnerable"]), tuple(sorted(item["cwes"]))) for item in items
        }
        if len(signatures) > 1:
            for item in items:
                conflicts.append({**item, "conflict_code_sha256": code_hash})
            continue
        primary = items[0]
        kept.append(primary)
        for item in items[1:]:
            duplicates.append({**item, "duplicate_of": primary["model_sample_id"]})
    return kept, duplicates, conflicts


def build(
    accepted_paths: Sequence[Path], chunk_paths: Sequence[Path], max_tokens: int = 512
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    raw_samples: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []
    for path in accepted_paths:
        for record in read_jsonl(path):
            raw_samples.extend(full_function_samples(record))
    for path in chunk_paths:
        fallback = "GitHub Advisory Database" if "supplement" in path.parts else "PyVul"
        for record in read_jsonl(path):
            sample = chunk_sample(record, fallback)
            if sample is not None:
                raw_samples.append(sample)
    valid: list[dict[str, Any]] = []
    for sample in raw_samples:
        errors = validate(sample, max_tokens)
        if errors:
            invalid.append({**sample, "validation_errors": errors})
        else:
            valid.append(sample)
    kept, duplicates, conflicts = deduplicate(valid)
    kept.sort(key=lambda row: str(row["model_sample_id"]))
    return kept, duplicates, conflicts, invalid


def write_summary(
    path: Path,
    samples: Sequence[Mapping[str, Any]],
    duplicates: Sequence[Mapping[str, Any]],
    conflicts: Sequence[Mapping[str, Any]],
    invalid: Sequence[Mapping[str, Any]],
) -> None:
    rows = [
        {"metric": "model_samples", "value": len(samples)},
        {"metric": "unique_parent_functions", "value": len({row["parent_sample_id"] for row in samples if row.get("unit_type", "function") == "function"})},
        {"metric": "unique_parent_module_blocks", "value": len({row["parent_sample_id"] for row in samples if row.get("unit_type") == "module_block"})},
        {"metric": "unique_parent_units", "value": len({row["parent_sample_id"] for row in samples})},
        {"metric": "unique_groups", "value": len({row["group_id"] for row in samples})},
        {"metric": "duplicates_removed", "value": len(duplicates)},
        {"metric": "label_conflicts_removed", "value": len(conflicts)},
        {"metric": "invalid_removed", "value": len(invalid)},
    ]
    for cwe, count in sorted(Counter(cwe for row in samples for cwe in row["cwes"]).items()):
        rows.append({"metric": f"samples_{cwe}", "value": count})
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["metric", "value"])
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--accepted",
        type=Path,
        nargs="*",
        default=[
            Path("data/processed-with-path/accepted.jsonl"),
            Path("data/supplement/cwe-798/processed/accepted.jsonl"),
            Path(
                "data/supplement/cwe-798/batches/crawl4ai-cve-2026-56265/"
                "processed/accepted.jsonl"
            ),
            Path(
                "data/supplement/cwe-78/batches/pillow-cve-2026-55798/"
                "processed/accepted.jsonl"
            ),
            Path(
                "data/supplement/cwe-78/batches/modoboa-cve-2026-27602/"
                "processed/accepted.jsonl"
            ),
            Path(
                "data/supplement/cwe-78/batches/octoprint-cve-2025-58180/"
                "processed/accepted.jsonl"
            ),
            Path(
                "data/supplement/cwe-287/batches/flask-httpauth-cve-2026-34531/"
                "processed/accepted.jsonl"
            ),
            Path(
                "data/supplement/cwe-89/batches/scitokens-cve-2026-32714/"
                "processed/accepted.jsonl"
            ),
            Path(
                "data/supplement/cwe-78/batches/mlflow-cve-2026-0596/"
                "processed/accepted.jsonl"
            ),
            Path(
                "data/supplement/cwe-22/batches/nltk-cve-2026-63312/"
                "processed/accepted.jsonl"
            ),
            Path(
                "data/supplement/cwe-22/batches/banks-cve-2026-71492/"
                "processed/accepted.jsonl"
            ),
            Path(
                "data/supplement/cwe-78/batches/ansys-geometry-cve-2024-29189/"
                "processed/accepted.jsonl"
            ),
            Path(
                "data/supplement/cwe-78/batches/yt-dlp-cve-2024-22423/"
                "processed/accepted.jsonl"
            ),
            Path(
                "data/supplement/cwe-79/batches/mistune-cve-2026-59926/"
                "processed/accepted.jsonl"
            ),
            Path(
                "data/supplement/cwe-79/batches/dosage-ghsa-75mw-h36v-2jv7/"
                "processed/accepted.jsonl"
            ),
            Path(
                "data/supplement/cwe-89/batches/pyload-cve-2025-55156/"
                "processed/accepted.jsonl"
            ),
            Path(
                "data/supplement/cwe-89/batches/glances-cve-2026-30930/"
                "processed/accepted.jsonl"
            ),
            Path(
                "data/supplement/cwe-287/batches/pysaml2-cve-2017-1000433/"
                "processed/accepted.jsonl"
            ),
            Path(
                "data/supplement/cwe-287/batches/drf-jwt-cve-2020-10594/"
                "processed/accepted.jsonl"
            ),
        ],
    )
    parser.add_argument(
        "--chunks",
        type=Path,
        nargs="*",
        default=[
            Path("data/codebert-ready/training_long_chunks.jsonl"),
            Path("data/supplement/cwe-798/codebert-ready/training_long_chunks.jsonl"),
            Path(
                "data/supplement/cwe-78/batches/octoprint-cve-2025-58180/"
                "codebert-ready/training_long_chunks.jsonl"
            ),
            Path(
                "data/supplement/cwe-287/batches/pytonapi-cve-2026-54635/"
                "codebert-ready/approved_training_chunks.jsonl"
            ),
            Path(
                "data/supplement/cwe-89/batches/parsl-cve-2026-21892/"
                "codebert-ready/training_long_chunks.jsonl"
            ),
            Path(
                "data/supplement/cwe-287/batches/prefect-cve-2026-7722/"
                "codebert-ready/training_long_chunks.jsonl"
            ),
        ],
    )
    parser.add_argument("--output-dir", type=Path, default=Path("data/model-dataset"))
    args = parser.parse_args()
    samples, duplicates, conflicts, invalid = build(args.accepted, args.chunks)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    atomic_jsonl(args.output_dir / "all_samples.jsonl", samples)
    atomic_jsonl(args.output_dir / "duplicates.jsonl", duplicates)
    atomic_jsonl(args.output_dir / "label_conflicts.jsonl", conflicts)
    atomic_jsonl(args.output_dir / "invalid_samples.jsonl", invalid)
    write_summary(args.output_dir / "build_summary.csv", samples, duplicates, conflicts, invalid)
    print(
        f"Built {len(samples)} model samples; duplicates={len(duplicates)}, "
        f"conflicts={len(conflicts)}, invalid={len(invalid)}"
    )
    print(f"Wrote outputs to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
