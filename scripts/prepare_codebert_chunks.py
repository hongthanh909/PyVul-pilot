#!/usr/bin/env python3
"""Prepare patch-aware CodeBERT chunks from long-only manual-review samples.

This is a post-filtering step. It reads only ``manual_review.jsonl`` and never
modifies the original dataset, accepted output, or rejected output. A record is
eligible only when its sole reason is ``manual_review_long_code``.
"""

from __future__ import annotations

import argparse
import csv
import difflib
import json
import os
import sys
import tempfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


DEFAULT_INPUT = Path("data/processed-with-path/manual_review.jsonl")
DEFAULT_OUTPUT_DIR = Path("data/codebert-ready")
DEFAULT_TOKENIZER = "microsoft/codebert-base"
DEFAULT_MAX_TOKENS = 512
DEFAULT_STRIDE = 128
LONG_REASON = "manual_review_long_code"


class ChunkingError(RuntimeError):
    """A fatal input or configuration error."""


@dataclass(frozen=True)
class PatchRegion:
    """A changed character range. start == end represents an edit anchor."""

    char_start: int
    char_end: int
    line_start: int
    line_end: int


@dataclass
class ProcessResult:
    all_chunks: list[dict[str, Any]]
    training_chunks: list[dict[str, Any]]
    remaining_manual: list[dict[str, Any]]
    function_outcomes: list[dict[str, Any]]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        handle = path.open("r", encoding="utf-8-sig")
    except OSError as exc:
        raise ChunkingError(f"Cannot read {path}: {exc}") from exc
    with handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ChunkingError(f"Invalid JSON at {path}:{line_number}: {exc}") from exc
            if not isinstance(row, dict):
                raise ChunkingError(f"Expected a JSON object at {path}:{line_number}")
            rows.append(row)
    return rows


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


def is_long_only(record: Mapping[str, Any]) -> bool:
    return set(record.get("reason_codes") or []) == {LONG_REASON}


def line_offsets(lines: Sequence[str]) -> list[int]:
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    return offsets


def make_region(offsets: Sequence[int], start: int, end: int) -> PatchRegion:
    char_start = offsets[start]
    char_end = offsets[end]
    # Lines are one-based in output. Empty edit ranges use their nearest anchor.
    line_start = min(start + 1, max(len(offsets) - 1, 1))
    line_end = max(line_start, min(end, max(len(offsets) - 1, 1)))
    return PatchRegion(char_start, char_end, line_start, line_end)


def find_patch_regions(code_before: str, code_after: str) -> tuple[list[PatchRegion], list[PatchRegion]]:
    before_lines = code_before.splitlines(keepends=True)
    after_lines = code_after.splitlines(keepends=True)
    before_offsets = line_offsets(before_lines)
    after_offsets = line_offsets(after_lines)
    matcher = difflib.SequenceMatcher(a=before_lines, b=after_lines, autojunk=False)
    before_regions: list[PatchRegion] = []
    after_regions: list[PatchRegion] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        # Insertions/deletions produce a zero-width anchor on one side. Keeping
        # the anchor lets us select contextual code from both before and after.
        before_regions.append(make_region(before_offsets, i1, i2))
        after_regions.append(make_region(after_offsets, j1, j2))
    return before_regions, after_regions


def region_overlaps(start: int, end: int, region: PatchRegion) -> bool:
    if region.char_start == region.char_end:
        return start <= region.char_start <= end
    return start < region.char_end and end > region.char_start


def chunk_contains_region(chunk: Mapping[str, Any], region: PatchRegion) -> bool:
    """Return whether a chunk contains the complete changed region or edit anchor."""
    start = int(chunk["char_start"])
    end = int(chunk["char_end"])
    if region.char_start == region.char_end:
        return start <= region.char_start <= end
    return start <= region.char_start and end >= region.char_end


def select_nonredundant_patch_chunks(
    chunks: Sequence[dict[str, Any]], regions: Sequence[PatchRegion]
) -> list[dict[str, Any]]:
    """Drop overlapping patch chunks whose changed regions are covered elsewhere.

    Sliding windows may place the same small patch in two adjacent chunks. Keeping
    both would overweight one side of a before/after pair. A chunk is redundant
    only when every patch region it touches is fully contained by another eligible
    chunk; large patches that span multiple windows therefore keep all necessary
    windows.
    """
    eligible = [chunk for chunk in chunks if chunk["eligible_for_training"]]
    selected: list[dict[str, Any]] = []
    for candidate in eligible:
        touched = [
            region
            for region in regions
            if region_overlaps(
                int(candidate["char_start"]), int(candidate["char_end"]), region
            )
        ]
        dominated = False
        for other in eligible:
            if other is candidate:
                continue
            if not touched or not all(chunk_contains_region(other, region) for region in touched):
                continue
            candidate_covers = sum(chunk_contains_region(candidate, region) for region in regions)
            other_covers = sum(chunk_contains_region(other, region) for region in regions)
            if other_covers > candidate_covers or (
                other_covers == candidate_covers
                and int(other["chunk_index"]) < int(candidate["chunk_index"])
            ):
                dominated = True
                break
        if dominated:
            candidate["eligible_for_training"] = False
            candidate["chunk_status"] = "CONTEXT_ONLY"
            candidate["chunk_reason_codes"] = ["context_redundant_patch_chunk"]
        else:
            selected.append(candidate)
    return selected


def token_count(tokenizer: Any, code: str) -> int:
    return len(tokenizer.encode(code, add_special_tokens=True, truncation=False))


def fit_text_to_limit(tokenizer: Any, text: str, max_tokens: int) -> str:
    """Trim only a possible tokenizer-boundary surplus from an exact source slice."""
    candidate = text
    for _ in range(4):
        if token_count(tokenizer, candidate) <= max_tokens:
            return candidate
        encoded = tokenizer(
            candidate,
            add_special_tokens=True,
            truncation=True,
            max_length=max_tokens,
            return_offsets_mapping=True,
        )
        offsets = encoded["offset_mapping"]
        ends = [int(end) for start, end in offsets if int(end) > int(start)]
        if not ends:
            return ""
        shorter = candidate[: max(ends)]
        if len(shorter) >= len(candidate):
            return ""
        candidate = shorter
    return candidate if token_count(tokenizer, candidate) <= max_tokens else ""


def chunk_code(
    tokenizer: Any,
    code: str,
    *,
    max_tokens: int,
    stride: int,
) -> list[dict[str, Any]]:
    encoded = tokenizer(
        code,
        add_special_tokens=True,
        truncation=True,
        max_length=max_tokens,
        stride=stride,
        return_overflowing_tokens=True,
        return_offsets_mapping=True,
        padding=False,
    )
    input_ids = encoded["input_ids"]
    offsets_collection = encoded["offset_mapping"]
    # Some tokenizer-like test doubles and old APIs may return one flat item.
    if input_ids and isinstance(input_ids[0], int):
        input_ids = [input_ids]
        offsets_collection = [offsets_collection]

    special_count = int(tokenizer.num_special_tokens_to_add(pair=False))
    content_capacity = max_tokens - special_count
    step = content_capacity - stride
    chunks: list[dict[str, Any]] = []
    for index, (ids, offsets) in enumerate(zip(input_ids, offsets_collection)):
        real_offsets = [(int(start), int(end)) for start, end in offsets if int(end) > int(start)]
        if not real_offsets:
            continue
        char_start = min(start for start, _ in real_offsets)
        char_end = max(end for _, end in real_offsets)
        chunk_text = fit_text_to_limit(tokenizer, code[char_start:char_end], max_tokens)
        if not chunk_text:
            continue
        char_end = char_start + len(chunk_text)
        exact_count = token_count(tokenizer, chunk_text)
        content_tokens = max(0, len(ids) - special_count)
        token_start = index * step
        chunks.append(
            {
                "chunk_code": chunk_text,
                "chunk_token_count": exact_count,
                "char_start": char_start,
                "char_end": char_end,
                "token_start": token_start,
                "token_end": token_start + content_tokens,
            }
        )
    return chunks


def base_chunk_record(
    record: Mapping[str, Any],
    *,
    variant: str,
    chunk: Mapping[str, Any],
    chunk_index: int,
    chunk_count: int,
    original_token_count: int,
    regions: Sequence[PatchRegion],
    max_tokens: int,
    stride: int,
    tokenizer_name: str,
) -> dict[str, Any]:
    contains_patch = any(
        region_overlaps(int(chunk["char_start"]), int(chunk["char_end"]), region)
        for region in regions
    )
    parent_id = str(record.get("sample_id") or f"SOURCE_LINE_{record.get('source_line', 'UNKNOWN')}")
    variant_name = variant.upper()
    result = {
        "chunk_id": f"{parent_id}_{variant_name}_CHUNK_{chunk_index:03d}",
        "parent_sample_id": parent_id,
        "pair_id": record.get("pair_id"),
        "schema_version": record.get("schema_version"),
        "source_dataset": record.get("source_dataset"),
        "source_dataset_url": record.get("source_dataset_url"),
        "source_license": record.get("source_license"),
        "source_record_id": record.get("source_record_id"),
        "advisory_ids": record.get("advisory_ids", []),
        "advisory_url": record.get("advisory_url") or record.get("report_link"),
        "source_line": record.get("source_line"),
        "repository": record.get("repository"),
        "repository_id": record.get("repository_id"),
        "commit": record.get("commit"),
        "commit_id": record.get("commit_id") or record.get("commit"),
        "commit_url": record.get("commit_url"),
        "file_path": record.get("file_path"),
        "function_name": record.get("function_name"),
        "unit_type": record.get("unit_type") or "function",
        "start_line_before": record.get("start_line_before"),
        "end_line_before": record.get("end_line_before"),
        "start_line_after": record.get("start_line_after"),
        "end_line_after": record.get("end_line_after"),
        "language": record.get("language"),
        "cwes": record.get("cwes", []),
        "labels": record.get("labels", []),
        "owasp_2025": record.get("owasp_2025", []),
        "variant": variant,
        "is_vulnerable_for_target_cwe": variant == "before",
        "has_paired_negative": record.get("has_paired_negative", False),
        "chunk_code": chunk["chunk_code"],
        "chunk_index": chunk_index,
        "chunk_count": chunk_count,
        "chunk_token_count": chunk["chunk_token_count"],
        "original_token_count": original_token_count,
        "char_start": chunk["char_start"],
        "char_end": chunk["char_end"],
        "token_start": chunk["token_start"],
        "token_end": chunk["token_end"],
        "contains_patch": contains_patch,
        "eligible_for_training": contains_patch,
        "patch_regions": [
            {
                "char_start": region.char_start,
                "char_end": region.char_end,
                "line_start": region.line_start,
                "line_end": region.line_end,
            }
            for region in regions
        ],
        "chunking_method": "codebert_patch_aware_sliding_window",
        "tokenizer": tokenizer_name,
        "max_tokens": max_tokens,
        "stride": stride,
        "source_status": record.get("status"),
        "source_reason_codes": record.get("reason_codes", []),
        "chunk_status": "MODEL_READY" if contains_patch else "CONTEXT_ONLY",
        "chunk_reason_codes": [
            "accepted_chunk_contains_patch" if contains_patch else "context_chunk_without_patch"
        ],
    }
    return result


def manual_copy(record: Mapping[str, Any], reason: str) -> dict[str, Any]:
    result = dict(record)
    result["chunking_status"] = "MANUAL_REVIEW"
    result["chunking_reason_codes"] = [reason]
    return result


def process_records(
    records: Sequence[Mapping[str, Any]],
    tokenizer: Any,
    *,
    tokenizer_name: str,
    max_tokens: int,
    stride: int,
) -> ProcessResult:
    all_chunks: list[dict[str, Any]] = []
    training_chunks: list[dict[str, Any]] = []
    remaining_manual: list[dict[str, Any]] = []
    outcomes: list[dict[str, Any]] = []

    for record in records:
        cwes = list(record.get("cwes") or [])
        outcome = {
            "sample_id": record.get("sample_id"),
            "cwes": cwes,
            "eligible_long_only": is_long_only(record),
            "within_limit": False,
            "chunked_model_ready": False,
            "chunks_created": 0,
            "training_chunks": 0,
            "max_chunk_token_count": 0,
        }
        if not is_long_only(record):
            remaining_manual.append(manual_copy(record, "manual_review_chunk_other_reasons"))
            outcomes.append(outcome)
            continue

        code_before = record.get("code_before") if isinstance(record.get("code_before"), str) else ""
        code_after = record.get("code_after") if isinstance(record.get("code_after"), str) else ""
        if not code_before.strip():
            remaining_manual.append(manual_copy(record, "manual_review_chunk_tokenization_error"))
            outcomes.append(outcome)
            continue
        if not code_after.strip():
            remaining_manual.append(manual_copy(record, "manual_review_chunk_missing_pair"))
            outcomes.append(outcome)
            continue

        before_count = token_count(tokenizer, code_before)
        after_count = token_count(tokenizer, code_after)
        outcome["within_limit"] = before_count <= max_tokens and after_count <= max_tokens
        before_regions, after_regions = find_patch_regions(code_before, code_after)
        if not before_regions and not after_regions:
            remaining_manual.append(manual_copy(record, "manual_review_chunk_patch_not_found"))
            outcomes.append(outcome)
            continue

        try:
            before_raw_chunks = chunk_code(
                tokenizer, code_before, max_tokens=max_tokens, stride=stride
            )
            after_raw_chunks = chunk_code(
                tokenizer, code_after, max_tokens=max_tokens, stride=stride
            )
        except Exception:
            remaining_manual.append(manual_copy(record, "manual_review_chunk_tokenization_error"))
            outcomes.append(outcome)
            continue
        if not before_raw_chunks or not after_raw_chunks:
            remaining_manual.append(manual_copy(record, "manual_review_chunk_tokenization_error"))
            outcomes.append(outcome)
            continue

        function_chunks: list[dict[str, Any]] = []
        for variant, raw_chunks, original_count, regions in (
            ("before", before_raw_chunks, before_count, before_regions),
            ("after", after_raw_chunks, after_count, after_regions),
        ):
            for index, raw_chunk in enumerate(raw_chunks, 1):
                function_chunks.append(
                    base_chunk_record(
                        record,
                        variant=variant,
                        chunk=raw_chunk,
                        chunk_index=index,
                        chunk_count=len(raw_chunks),
                        original_token_count=original_count,
                        regions=regions,
                        max_tokens=max_tokens,
                        stride=stride,
                        tokenizer_name=tokenizer_name,
                    )
                )

        before_training = select_nonredundant_patch_chunks(
            [chunk for chunk in function_chunks if chunk["variant"] == "before"],
            before_regions,
        )
        after_training = select_nonredundant_patch_chunks(
            [chunk for chunk in function_chunks if chunk["variant"] == "after"],
            after_regions,
        )
        if not before_training or not after_training:
            for chunk in function_chunks:
                chunk["eligible_for_training"] = False
                chunk["chunk_status"] = "MANUAL_REVIEW"
                chunk["chunk_reason_codes"] = ["manual_review_chunk_patch_not_found"]
            all_chunks.extend(function_chunks)
            remaining_manual.append(manual_copy(record, "manual_review_chunk_patch_not_found"))
        else:
            all_chunks.extend(function_chunks)
            selected = before_training + after_training
            training_chunks.extend(selected)
            outcome["chunked_model_ready"] = True

        outcome["chunks_created"] = len(function_chunks)
        outcome["training_chunks"] = len(before_training) + len(after_training) if outcome["chunked_model_ready"] else 0
        outcome["max_chunk_token_count"] = max(
            (int(chunk["chunk_token_count"]) for chunk in function_chunks), default=0
        )
        outcomes.append(outcome)

    return ProcessResult(all_chunks, training_chunks, remaining_manual, outcomes)


SUMMARY_COLUMNS = [
    "cwe",
    "input_manual_samples",
    "eligible_long_only_functions",
    "functions_within_limit",
    "long_functions",
    "chunked_model_ready_functions",
    "chunks_created",
    "training_chunks",
    "non_patch_chunks",
    "remaining_manual_review",
    "max_chunk_token_count",
]


def build_summary(
    records: Sequence[Mapping[str, Any]], result: ProcessResult
) -> list[dict[str, Any]]:
    cwes = sorted(
        {str(cwe) for record in records for cwe in record.get("cwes", [])},
        key=lambda value: int(value.split("-", 1)[1]) if "-" in value else value,
    )
    rows: list[dict[str, Any]] = []
    for cwe in cwes + ["TOTAL"]:
        record_matches = [
            record for record in records if cwe == "TOTAL" or cwe in record.get("cwes", [])
        ]
        outcome_matches = [
            outcome for outcome in result.function_outcomes if cwe == "TOTAL" or cwe in outcome["cwes"]
        ]
        chunks = [
            chunk for chunk in result.all_chunks if cwe == "TOTAL" or cwe in chunk.get("cwes", [])
        ]
        remaining = [
            record
            for record in result.remaining_manual
            if cwe == "TOTAL" or cwe in record.get("cwes", [])
        ]
        rows.append(
            {
                "cwe": cwe,
                "input_manual_samples": len(record_matches),
                "eligible_long_only_functions": sum(item["eligible_long_only"] for item in outcome_matches),
                "functions_within_limit": sum(item["within_limit"] for item in outcome_matches),
                "long_functions": sum(
                    item["eligible_long_only"] and not item["within_limit"] for item in outcome_matches
                ),
                "chunked_model_ready_functions": sum(item["chunked_model_ready"] for item in outcome_matches),
                "chunks_created": len(chunks),
                "training_chunks": sum(chunk["eligible_for_training"] for chunk in chunks),
                "non_patch_chunks": sum(not chunk["contains_patch"] for chunk in chunks),
                "remaining_manual_review": len(remaining),
                "max_chunk_token_count": max(
                    (int(chunk["chunk_token_count"]) for chunk in chunks), default=0
                ),
            }
        )
    return rows


def load_tokenizer(name: str, offline: bool) -> Any:
    try:
        from transformers import AutoTokenizer  # type: ignore

        tokenizer = AutoTokenizer.from_pretrained(
            name,
            use_fast=True,
            local_files_only=offline,
        )
    except Exception as exc:
        raise ChunkingError(f"Cannot load tokenizer {name!r}: {exc}") from exc
    if not getattr(tokenizer, "is_fast", False):
        raise ChunkingError("A fast tokenizer is required for offset_mapping")
    return tokenizer


def validate_result(result: ProcessResult, max_tokens: int) -> None:
    oversized = [
        chunk["chunk_id"]
        for chunk in result.all_chunks
        if int(chunk["chunk_token_count"]) > max_tokens
    ]
    if oversized:
        raise ChunkingError(f"Generated chunks over {max_tokens} tokens: {oversized[:5]}")
    ids = [str(chunk["chunk_id"]) for chunk in result.all_chunks]
    if len(ids) != len(set(ids)):
        raise ChunkingError("Duplicate chunk_id values were generated")
    if any(not chunk.get("parent_sample_id") for chunk in result.all_chunks):
        raise ChunkingError("At least one chunk has no parent_sample_id")
    if any(not chunk.get("contains_patch") for chunk in result.training_chunks):
        raise ChunkingError("A training chunk does not overlap the patch")


def run(args: argparse.Namespace) -> ProcessResult:
    if not args.input.is_file():
        raise ChunkingError(f"Input does not exist: {args.input}")
    if args.max_tokens <= 2:
        raise ChunkingError("--max-tokens must be greater than two")
    tokenizer = load_tokenizer(args.tokenizer, args.offline)
    special_count = int(tokenizer.num_special_tokens_to_add(pair=False))
    content_capacity = args.max_tokens - special_count
    if args.stride < 0 or args.stride >= content_capacity:
        raise ChunkingError(
            f"--stride must be between 0 and {content_capacity - 1} for this tokenizer"
        )
    records = read_jsonl(args.input)
    result = process_records(
        records,
        tokenizer,
        tokenizer_name=args.tokenizer,
        max_tokens=args.max_tokens,
        stride=args.stride,
    )
    validate_result(result, args.max_tokens)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_jsonl(args.output_dir / "all_long_chunks.jsonl", result.all_chunks)
    atomic_write_jsonl(args.output_dir / "training_long_chunks.jsonl", result.training_chunks)
    atomic_write_jsonl(
        args.output_dir / "remaining_manual_review.jsonl", result.remaining_manual
    )
    write_csv(
        args.output_dir / "chunking_summary.csv",
        SUMMARY_COLUMNS,
        build_summary(records, result),
    )
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create patch-aware CodeBERT chunks from long-only manual-review records.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--tokenizer", default=DEFAULT_TOKENIZER)
    parser.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS)
    parser.add_argument("--stride", type=int, default=DEFAULT_STRIDE)
    parser.add_argument("--offline", action="store_true", help="Use only cached tokenizer files")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run(args)
    except (ChunkingError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    function_count = sum(item["chunked_model_ready"] for item in result.function_outcomes)
    print(
        f"Chunking complete: model_ready_functions={function_count}, "
        f"all_chunks={len(result.all_chunks)}, "
        f"training_chunks={len(result.training_chunks)}, "
        f"remaining_manual={len(result.remaining_manual)}"
    )
    print(f"Wrote outputs to {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
