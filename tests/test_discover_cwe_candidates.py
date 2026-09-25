from scripts.discover_cwe_candidates import next_link, normalize_candidate


def test_candidate_with_exact_cwe_and_commit_is_ready():
    row = normalize_candidate(
        {
            "ghsa_id": "GHSA-test-test-test",
            "cwes": [{"cwe_id": "CWE-798"}],
            "references": [
                "https://github.com/example/project/commit/0123456789abcdef"
            ],
        },
        798,
    )
    assert row["candidate_status"] == "READY_FOR_EXTRACTION"
    assert row["fix_commits"][0]["repository"] == "example/project"


def test_candidate_without_commit_requires_manual_commit_lookup():
    row = normalize_candidate(
        {
            "ghsa_id": "GHSA-test-test-test",
            "cwes": [{"cwe_id": "CWE-798"}],
            "references": ["https://example.com/report"],
        },
        798,
    )
    assert row["candidate_status"] == "NEEDS_FIX_COMMIT"
    assert row["fix_commits"] == []


def test_parses_next_cursor_link():
    header = '<https://api.github.com/advisories?after=abc>; rel="next", <x>; rel="last"'
    assert next_link(header) == "https://api.github.com/advisories?after=abc"
