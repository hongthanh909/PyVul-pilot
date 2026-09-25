from scripts.extract_github_function_pairs import (
    ChangedFile,
    FunctionSpan,
    affected,
    collect_functions,
    make_pair,
    module_binding_block,
    parse_diff,
    extract_candidates,
)


def test_parse_diff_tracks_old_and_new_lines():
    patch = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -2,2 +2,2 @@
-    secret = \"fixed\"
+    secret = make_secret()
     return secret
"""
    changed = parse_diff(patch)[0]
    assert changed.old_lines == {2}
    assert changed.new_lines == {2}


def test_collects_changed_nested_qualified_function():
    source = """class App:
    def build(self):
        secret = \"fixed\"
        return secret
"""
    functions = collect_functions(source)
    result = affected(functions, {3})
    assert set(result) == {"App.build"}
    assert 'secret = "fixed"' in result["App.build"].code


def test_make_pair_uses_candidate_cwe_instead_of_hardcoded_cwe798():
    candidate = {
        "ghsa_id": "GHSA-example",
        "cve_id": "CVE-2026-1",
        "target_cwe": "CWE-78",
        "cwes": ["CWE-78"],
        "advisory_url": "https://github.com/advisories/GHSA-example",
        "summary": "Command injection",
        "platform": "Windows",
        "curation_status": "APPROVED_FOR_STAGING",
    }
    before = FunctionSpan("Viewer.show", 1, 2, "def show():\n    run_shell()\n")
    after = FunctionSpan("Viewer.show", 1, 2, "def show():\n    safe_api()\n")
    pair = make_pair(
        candidate,
        "owner/project",
        "a" * 40,
        "b" * 40,
        "fix command injection",
        ChangedFile("src/view.py", "src/view.py", {2}, {2}),
        before,
        after,
        1,
    )
    assert pair["cwes"] == ["CWE-78"]
    assert pair["labels"] == ["COMMAND_INJECTION"]
    assert pair["sample_id"].startswith("GHSA_CWE78_")
    assert pair["platform"] == "Windows"
    assert pair["unit_type"] == "function"
    assert pair["start_line_before"] == 1


def test_module_binding_keeps_only_assignment_and_required_helper():
    source = '''import os
UNRELATED = "other"
_WEAK_SECRETS = {"mysecret"}

def _resolve_secret_key():
    key = os.environ.get("SECRET_KEY", "")
    if key in _WEAK_SECRETS:
        raise RuntimeError("weak")
    return key

SECRET_KEY = _resolve_secret_key()

def unrelated():
    return 3
'''
    result = module_binding_block(source, "SECRET_KEY")
    assert result is not None
    block, spans = result
    assert block.qualified_name == "module:SECRET_KEY"
    assert "_WEAK_SECRETS" in block.code
    assert "def _resolve_secret_key" in block.code
    assert "UNRELATED =" not in block.code
    assert "def unrelated" not in block.code
    assert len(spans) == 3


def test_module_binding_includes_later_conditional_overwrite():
    source = '''_DEFAULT_SECRET = "dev-secret-change-me"
JWT_SECRET = os.environ.get("PLATFORM_JWT_SECRET")
if JWT_SECRET is None:
    if os.environ.get("PLATFORM_ENV") == "dev":
        JWT_SECRET = _DEFAULT_SECRET
    else:
        JWT_SECRET = secrets.token_urlsafe(32)
'''
    block, spans = module_binding_block(source, "JWT_SECRET")
    assert "JWT_SECRET = _DEFAULT_SECRET" in block.code
    assert "_DEFAULT_SECRET =" in block.code
    assert len(spans) == 3


def test_multi_cwe_module_requires_explicit_isolation_evidence():
    candidate = {
        "ghsa_id": "GHSA-example",
        "candidate_status": "READY_FOR_EXTRACTION",
        "target_cwe": "CWE-798",
        "cwes": ["CWE-287", "CWE-798"],
        "include_module_bindings": ["JWT_SECRET"],
        "fix_commits": [],
    }
    pairs, review = extract_candidates([candidate], None)
    assert pairs == []
    assert review[0]["reason"] == "rejected_module_scope_without_cwe798_isolation_evidence"


def test_isolated_cwe_cannot_relabel_arbitrary_function():
    candidate = {
        "ghsa_id": "GHSA-example",
        "candidate_status": "READY_FOR_EXTRACTION",
        "target_cwe": "CWE-798",
        "cwes": ["CWE-287", "CWE-798"],
        "isolated_target_cwe": "CWE-798",
        "fix_commits": [],
    }
    pairs, review = extract_candidates([candidate], None)
    assert pairs == []
    assert review[0]["reason"] == "rejected_isolated_cwe_requires_module_binding_scope"
