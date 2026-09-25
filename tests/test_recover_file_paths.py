import unittest

from scripts.recover_file_paths import choose_candidate, parse_unified_diff


SAMPLE_DIFF = """diff --git a/src/download.py b/src/download.py
index 1111111..2222222 100644
--- a/src/download.py
+++ b/src/download.py
@@ -1,2 +1,3 @@
 def download_file(name):
-    return open('/tmp/' + name).read()
+    safe = os.path.basename(name)
+    return open('/tmp/' + safe).read()
diff --git a/tests/test_download.py b/tests/test_download.py
index 3333333..4444444 100644
--- a/tests/test_download.py
+++ b/tests/test_download.py
@@ -1,2 +1,2 @@
 def test_download():
-    assert download_file('a')
+    assert download_file('../a')
"""


class RecoverFilePathsTests(unittest.TestCase):
    def test_parse_diff_paths_and_changed_lines(self):
        files = parse_unified_diff(SAMPLE_DIFF)
        self.assertEqual([item.preferred_path for item in files], ["src/download.py", "tests/test_download.py"])
        self.assertIn("return open('/tmp/' + name).read()", files[0].deleted)
        self.assertIn("safe = os.path.basename(name)", files[0].added)

    def test_unique_function_match_is_resolved(self):
        rows = [
            {
                "function_name": "download_file",
                "programming_language": "Python",
                "code_before": "def download_file(name):\n    return open('/tmp/' + name).read()\n",
                "code_after": "def download_file(name):\n    safe = os.path.basename(name)\n    return open('/tmp/' + safe).read()\n",
            }
        ]
        best, reason, _ = choose_candidate(rows, parse_unified_diff(SAMPLE_DIFF))
        self.assertIsNotNone(best)
        self.assertEqual(best.path, "src/download.py")
        self.assertEqual(reason, "unique_high_confidence_diff_match")

    def test_context_only_match_is_not_accepted(self):
        rows = [
            {
                "function_name": "download_file",
                "programming_language": "Python",
                "code_before": "def download_file(name):\n    unchanged()\n",
                "code_after": "def download_file(name):\n    unchanged()\n",
            }
        ]
        best, reason, _ = choose_candidate(rows, parse_unified_diff(SAMPLE_DIFF))
        self.assertIsNone(best)
        self.assertEqual(reason, "missing_before_or_after_change_match")


if __name__ == "__main__":
    unittest.main()
