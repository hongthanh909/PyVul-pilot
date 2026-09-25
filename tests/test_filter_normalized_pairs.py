from types import SimpleNamespace

from scripts.filter_normalized_pairs import build_record, hardcoded_credentials


class FakeCounter:
    model_name = "fake"

    def count(self, code):
        return SimpleNamespace(count=len(code.split()) + 2, exact=True, method="fake")


def base_record():
    return {
        "schema_version": "1.0",
        "sample_id": "EXT_1",
        "source_dataset": "test",
        "source_dataset_url": "https://example.test/data",
        "source_record_id": "ADV-1",
        "repository": "example/repo",
        "commit_id": "0123456789abcdef",
        "commit_url": "https://github.com/example/repo/commit/0123456789abcdef",
        "file_path": "app.py",
        "function_name": "build",
        "language": "Python",
        "cwes": ["CWE-798"],
        "code_before": 'def build():\n    secret_key = "fixed-secret"\n',
        "code_after": "def build():\n    secret_key = make_secret()\n",
    }


def test_detects_removed_hardcoded_credential():
    assert ("secret_key", "fixed-secret") in hardcoded_credentials(base_record()["code_before"])
    result = build_record({**base_record(), "_input_line": 1}, FakeCounter(), 512)
    assert result["status"] == "ACCEPTED"


def test_exact_cwe_without_local_semantic_evidence_is_manual():
    row = base_record()
    row["code_before"] = "def build():\n    return GLOBAL_SECRET\n"
    row["code_after"] = 'def build():\n    return config["secret"]\n'
    result = build_record({**row, "_input_line": 1}, FakeCounter(), 512)
    assert result["status"] == "MANUAL_REVIEW"
    assert "manual_review_cwe798_semantic_evidence" in result["reason_codes"]


def test_cwe798_module_environment_fallback_pair_is_accepted():
    row = base_record()
    row.update({
        "function_name": "module:SECRET_KEY",
        "unit_type": "module_block",
        "start_line_before": 13,
        "end_line_before": 13,
        "start_line_after": 14,
        "end_line_after": 15,
        "code_before": 'SECRET_KEY = os.environ.get("SECRET_KEY", "mysecret")\n',
        "code_after": 'def resolve():\n    return make_key()\n\nSECRET_KEY = resolve()\n',
    })
    result = build_record(row, FakeCounter(), 512)
    assert result["status"] == "ACCEPTED"
    assert ("secret_key", "mysecret") in hardcoded_credentials(row["code_before"])


def test_module_scope_is_not_enabled_for_other_cwes():
    row = base_record()
    row.update({
        "unit_type": "module_block",
        "function_name": "module:SECRET_KEY",
        "cwes": ["CWE-78"],
        "start_line_before": 1,
        "end_line_before": 2,
        "start_line_after": 1,
        "end_line_after": 2,
    })
    result = build_record(row, FakeCounter(), 512)
    assert result["status"] == "MANUAL_REVIEW"


def test_module_block_cannot_use_unrelated_function_literal_as_evidence():
    row = base_record()
    row.update({
        "function_name": "module:SECRET_KEY",
        "unit_type": "module_block",
        "start_line_before": 1,
        "end_line_before": 4,
        "start_line_after": 1,
        "end_line_after": 4,
        "code_before": 'def unrelated():\n    password = "fixed-secret"\nSECRET_KEY = get_key()\n',
        "code_after": 'def unrelated():\n    password = make_key()\nSECRET_KEY = get_key()\n',
    })
    result = build_record(row, FakeCounter(), 512)
    assert result["status"] == "MANUAL_REVIEW"
    assert "manual_review_cwe798_semantic_evidence" in result["reason_codes"]


def test_module_alias_and_dev_fallback_prevent_false_safe_label():
    row = base_record()
    row.update({
        "function_name": "module:JWT_SECRET",
        "unit_type": "module_block",
        "start_line_before": 1,
        "end_line_before": 2,
        "start_line_after": 1,
        "end_line_after": 7,
        "code_before": '_DEFAULT_SECRET = "dev-secret-change-me"\nJWT_SECRET = os.environ.get("PLATFORM_JWT_SECRET", _DEFAULT_SECRET)\n',
        "code_after": '_DEFAULT_SECRET = "dev-secret-change-me"\nJWT_SECRET = os.environ.get("PLATFORM_JWT_SECRET")\nif JWT_SECRET is None:\n    if os.environ.get("PLATFORM_ENV") == "dev":\n        JWT_SECRET = _DEFAULT_SECRET\n    else:\n        JWT_SECRET = secrets.token_urlsafe(32)\n',
    })
    result = build_record(row, FakeCounter(), 512)
    assert ("jwt_secret", "dev-secret-change-me") in hardcoded_credentials(row["code_before"])
    assert ("jwt_secret", "dev-secret-change-me") in hardcoded_credentials(row["code_after"])
    assert result["status"] == "MANUAL_REVIEW"
    assert "manual_review_cwe798_residual_hardcoded_credential" in result["reason_codes"]


def test_multi_cwe_advisory_requires_isolation_evidence():
    row = base_record()
    row["advisory_cwes"] = ["CWE-287", "CWE-798"]
    result = build_record(row, FakeCounter(), 512)
    assert result["status"] == "MANUAL_REVIEW"
    assert "manual_review_multi_cwe_without_isolation_evidence" in result["reason_codes"]
