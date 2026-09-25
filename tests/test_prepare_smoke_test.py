from scripts.prepare_smoke_test import (
    allocate_groups,
    build_splits,
    prepare_rows,
    validate_splits,
)


LABEL_MAP = {"SAFE": 0, "CWE-22": 1, "CWE-78": 2}


def row(sample_id, repository, commit, variant, cwe):
    return {
        "model_sample_id": sample_id,
        "repository": repository,
        "commit_id": commit,
        "file_path": "app.py",
        "function_name": "run",
        "code": "def run():\n    pass\n",
        "variant": variant,
        "is_vulnerable": variant == "before",
        "cwes": [cwe],
        "token_count": 8,
        "tokenizer": "test",
    }


def test_fixed_variant_becomes_safe_and_commit_stays_together():
    source = []
    for cwe in ("CWE-22", "CWE-78"):
        for index in range(3):
            commit = f"{index + 1:07x}"
            source.append(row(f"{cwe}-{index}-b", f"owner/{cwe.lower()}", commit, "before", cwe))
            source.append(row(f"{cwe}-{index}-a", f"owner/{cwe.lower()}", commit, "after", cwe))
    prepared, excluded = prepare_rows(source, LABEL_MAP, set(), 512)
    assert excluded == 0
    assert sum(item["target_label"] == "SAFE" for item in prepared) == 6
    groups = {}
    for item in prepared:
        groups.setdefault(item["split_group_id"], []).append(item)
    assignment = allocate_groups(groups, validation_ratio=0.2, test_ratio=0.2, seed=42)
    splits = build_splits(prepared, assignment)
    validate_splits(splits, set(LABEL_MAP))
    locations = {}
    for split, values in splits.items():
        for item in values:
            locations.setdefault(item["split_group_id"], set()).add(split)
    assert all(len(value) == 1 for value in locations.values())


def test_excluded_cwe_is_removed_before_split():
    source = [row("x", "owner/repo", "abcdef0", "before", "CWE-798")]
    prepared, excluded = prepare_rows(source, LABEL_MAP, {"CWE-798"}, 512)
    assert prepared == []
    assert excluded == 1
