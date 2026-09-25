#!/usr/bin/env python3
"""Create leakage-safe train/validation/test files for a CodeBERT smoke test.

Input rows already conform to ``schemas/model_sample.schema.json``.  This step
derives the actual classification target (fixed code -> SAFE), temporarily
excludes under-supported CWEs, and keeps every row from one repository+commit
in the same split.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


DEFAULT_LABELS = ["SAFE", "CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-287"]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"Expected object at {path}:{line_number}")
            rows.append(value)
    return rows


def atomic_jsonl(path: Path, rows: Iterable[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", delete=False, dir=path.parent
    ) as handle:
        temporary = Path(handle.name)
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    os.replace(temporary, path)


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", newline="\n", delete=False, dir=path.parent
    ) as handle:
        temporary = Path(handle.name)
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    os.replace(temporary, path)


def target_label(row: Mapping[str, Any]) -> str:
    variant = row.get("variant")
    cwes = row.get("cwes") or []
    if variant == "after" or row.get("is_vulnerable") is False:
        return "SAFE"
    if variant != "before" or row.get("is_vulnerable") is not True:
        raise ValueError(f"Inconsistent variant/vulnerability: {row.get('model_sample_id')}")
    if not isinstance(cwes, list) or len(cwes) != 1:
        raise ValueError(f"Smoke test requires exactly one CWE: {row.get('model_sample_id')}")
    return str(cwes[0])


def split_group_id(row: Mapping[str, Any]) -> str:
    repository = str(row.get("repository") or "").strip().lower()
    commit_id = str(row.get("commit_id") or "").strip().lower()
    if not repository or not commit_id:
        raise ValueError(f"Missing repository/commit: {row.get('model_sample_id')}")
    return f"{repository}@{commit_id}"


def validate_source_row(row: Mapping[str, Any], max_tokens: int) -> None:
    required = (
        "model_sample_id",
        "repository",
        "commit_id",
        "file_path",
        "function_name",
        "code",
        "variant",
        "is_vulnerable",
        "cwes",
        "token_count",
        "tokenizer",
    )
    missing = [key for key in required if row.get(key) in (None, "", [])]
    if missing:
        raise ValueError(f"{row.get('model_sample_id')}: missing {missing}")
    if not str(row["file_path"]).endswith(".py"):
        raise ValueError(f"{row['model_sample_id']}: non-Python file path")
    if not isinstance(row["token_count"], int) or not 1 <= row["token_count"] <= max_tokens:
        raise ValueError(f"{row['model_sample_id']}: invalid token_count={row['token_count']}")


def prepare_rows(
    rows: Sequence[Mapping[str, Any]],
    label_map: Mapping[str, int],
    excluded_cwes: set[str],
    max_tokens: int,
) -> tuple[list[dict[str, Any]], int]:
    prepared: list[dict[str, Any]] = []
    excluded = 0
    for source in rows:
        validate_source_row(source, max_tokens)
        cwes = {str(value) for value in source.get("cwes") or []}
        if cwes & excluded_cwes:
            excluded += 1
            continue
        label = target_label(source)
        if label not in label_map:
            raise ValueError(f"Unknown target label {label!r} in {source.get('model_sample_id')}")
        row = dict(source)
        row["target_label"] = label
        row["label_id"] = int(label_map[label])
        row["split_group_id"] = split_group_id(source)
        prepared.append(row)
    return prepared, excluded


def group_rows(rows: Sequence[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        result[str(row["split_group_id"])].append(row)
    return dict(result)


def group_cwe(rows: Sequence[Mapping[str, Any]]) -> str:
    labels = {str(row["target_label"]) for row in rows if row["target_label"] != "SAFE"}
    if len(labels) != 1:
        raise ValueError(f"One commit group must have one vulnerable CWE, found {sorted(labels)}")
    return next(iter(labels))


def allocate_groups(
    groups: Mapping[str, list[dict[str, Any]]],
    *,
    validation_ratio: float,
    test_ratio: float,
    seed: int,
) -> dict[str, str]:
    by_cwe: dict[str, list[str]] = defaultdict(list)
    for key, items in groups.items():
        by_cwe[group_cwe(items)].append(key)
    assignment: dict[str, str] = {}
    rng = random.Random(seed)
    for cwe, keys in sorted(by_cwe.items()):
        keys = sorted(keys)
        rng.shuffle(keys)
        count = len(keys)
        if count < 3:
            raise ValueError(f"{cwe} needs at least 3 independent commit groups, found {count}")
        test_count = max(1, round(count * test_ratio))
        validation_count = max(1, round(count * validation_ratio))
        while test_count + validation_count >= count:
            if test_count >= validation_count and test_count > 1:
                test_count -= 1
            elif validation_count > 1:
                validation_count -= 1
            else:
                break
        for key in keys[:test_count]:
            assignment[key] = "test"
        for key in keys[test_count : test_count + validation_count]:
            assignment[key] = "validation"
        for key in keys[test_count + validation_count :]:
            assignment[key] = "train"
    return assignment


def build_splits(
    rows: Sequence[dict[str, Any]], assignment: Mapping[str, str]
) -> dict[str, list[dict[str, Any]]]:
    splits = {"train": [], "validation": [], "test": []}
    for row in rows:
        split = assignment[str(row["split_group_id"])]
        splits[split].append(row)
    for values in splits.values():
        values.sort(key=lambda row: str(row["model_sample_id"]))
    return splits


def validate_splits(splits: Mapping[str, Sequence[Mapping[str, Any]]], labels: set[str]) -> None:
    group_sets: dict[str, set[str]] = {}
    for split, rows in splits.items():
        if not rows:
            raise ValueError(f"{split} is empty")
        present = {str(row["target_label"]) for row in rows}
        missing = labels - present
        if missing:
            raise ValueError(f"{split} is missing labels: {sorted(missing)}")
        group_sets[split] = {str(row["split_group_id"]) for row in rows}
    if group_sets["train"] & group_sets["validation"]:
        raise ValueError("Group leakage between train and validation")
    if group_sets["train"] & group_sets["test"]:
        raise ValueError("Group leakage between train and test")
    if group_sets["validation"] & group_sets["test"]:
        raise ValueError("Group leakage between validation and test")


def write_summary(path: Path, splits: Mapping[str, Sequence[Mapping[str, Any]]]) -> None:
    fields = ["split", "label", "samples", "commit_groups", "repositories"]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for split in ("train", "validation", "test"):
            rows = splits[split]
            for label in sorted({str(row["target_label"]) for row in rows}):
                selected = [row for row in rows if row["target_label"] == label]
                writer.writerow(
                    {
                        "split": split,
                        "label": label,
                        "samples": len(selected),
                        "commit_groups": len({row["split_group_id"] for row in selected}),
                        "repositories": len({row["repository"] for row in selected}),
                    }
                )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=Path("data/model-dataset/all_samples.jsonl"))
    parser.add_argument("--output-dir", type=Path, default=Path("data/smoke-test"))
    parser.add_argument("--exclude-cwe", action="append", default=["CWE-798"])
    parser.add_argument("--validation-ratio", type=float, default=0.15)
    parser.add_argument("--test-ratio", type=float, default=0.15)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--max-tokens", type=int, default=512)
    args = parser.parse_args(argv)
    if args.validation_ratio <= 0 or args.test_ratio <= 0:
        raise ValueError("Validation and test ratios must be positive")
    if args.validation_ratio + args.test_ratio >= 1:
        raise ValueError("Validation + test ratios must be less than 1")

    label_map = {label: index for index, label in enumerate(DEFAULT_LABELS)}
    source = read_jsonl(args.input)
    rows, excluded = prepare_rows(source, label_map, set(args.exclude_cwe), args.max_tokens)
    groups = group_rows(rows)
    assignment = allocate_groups(
        groups,
        validation_ratio=args.validation_ratio,
        test_ratio=args.test_ratio,
        seed=args.seed,
    )
    splits = build_splits(rows, assignment)
    validate_splits(splits, set(label_map))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    for split, values in splits.items():
        atomic_jsonl(args.output_dir / f"{split}.jsonl", values)
    atomic_json(args.output_dir / "label_map.json", label_map)
    write_summary(args.output_dir / "split_summary.csv", splits)
    counts = {name: len(values) for name, values in splits.items()}
    print(
        f"Prepared smoke-test data: train={counts['train']}, "
        f"validation={counts['validation']}, test={counts['test']}, excluded={excluded}"
    )
    print(f"Commit groups: {len(groups)}; seed={args.seed}")
    print(f"Wrote outputs to {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
