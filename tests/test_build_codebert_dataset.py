from scripts.build_codebert_dataset import deduplicate, full_function_samples, validate


def accepted_record():
    return {
        "sample_id": "PAIR-1",
        "pair_id": "group-1",
        "source_dataset": "test",
        "repository": "owner/repo",
        "commit_id": "0123456789abcdef",
        "commit_url": "https://github.com/owner/repo/commit/0123456789abcdef",
        "file_path": "app.py",
        "function_name": "run",
        "cwes": ["CWE-798"],
        "labels": ["HARDCODED_CREDENTIALS"],
        "tokenizer": "test",
        "code_before": 'def run():\n    secret = "fixed"\n',
        "code_after": "def run():\n    secret = make_secret()\n",
        "token_count_before": 12,
        "token_count_after": 13,
        "platform": "Windows",
        "domain": "Python library",
    }


def test_pair_becomes_positive_and_negative_model_samples():
    samples = full_function_samples(accepted_record())
    assert len(samples) == 2
    assert [row["is_vulnerable"] for row in samples] == [True, False]
    assert all(row["platform"] == "Windows" for row in samples)
    assert all(row["domain"] == "Python library" for row in samples)
    assert all(not validate(row) for row in samples)


def test_conflicting_exact_code_is_removed():
    samples = full_function_samples(accepted_record())
    conflict = dict(samples[0])
    conflict["model_sample_id"] = "other"
    conflict["is_vulnerable"] = False
    kept, duplicates, conflicts = deduplicate([samples[0], conflict])
    assert kept == []
    assert duplicates == []
    assert len(conflicts) == 2


def test_module_block_type_and_location_reach_model_samples():
    row = accepted_record()
    row.update({
        "unit_type": "module_block",
        "function_name": "module:SECRET_KEY",
        "start_line_before": 13,
        "end_line_before": 13,
        "start_line_after": 14,
        "end_line_after": 45,
    })
    samples = full_function_samples(row)
    assert all(sample["source_type"] == "module_block" for sample in samples)
    assert all(sample["unit_type"] == "module_block" for sample in samples)
    assert samples[0]["start_line_before"] == 13
    assert [sample["start_line"] for sample in samples] == [13, 14]
