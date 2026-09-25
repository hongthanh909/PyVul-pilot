import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.filter_pyvul import TokenCount, filter_dataset, normalize_commit


class ExactTestTokenCounter:
    def __init__(self, model_name, **kwargs):
        self.model_name = model_name

    def count(self, code):
        return TokenCount(len(code.split()) + 2, True, self.model_name)


class PyVulFilterTests(unittest.TestCase):
    def write_inputs(self, root: Path) -> argparse.Namespace:
        commit1 = "https://github.com/acme/app/commit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        commit2 = "https://github.com/acme/app/commit/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        rows = [
            {
                "function_name": "run",
                "code_before": "def run(value):\n    return value\n",
                "code_after": "def run(value):\n    return str(value)\n",
                "commit": commit1,
                "programming_language": "Python",
                "file_change_id": 1,
            },
            {
                "function_name": "run_copy",
                "code_before": "def run(value):\n    return value\n",
                "code_after": "def run(value):\n    return str(value)\n",
                "commit": commit1,
                "programming_language": "Python",
                "file_change_id": 2,
            },
            {
                "function_name": "shell",
                "code_before": "def shell(cmd):\n    return cmd\n",
                "code_after": "def shell(cmd):\n    return [cmd]\n",
                "commit": commit2,
                "programming_language": "JavaScript",
                "file_change_id": 3,
            },
        ]
        function_path = root / "functions.out"
        function_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        cwe_path = root / "map.json"
        cwe_path.write_text(json.dumps({commit1: "CWE-22", commit2: "CWE-78"}), encoding="utf-8")
        commits_path = root / "commits.out"
        commits_path.write_text(commit1 + "\n" + commit2 + "\n", encoding="utf-8")
        metadata_path = root / "metadata.jsonl"
        metadata_path.write_text(
            "\n".join(
                [
                    json.dumps({"file_change_id": 1, "file_path": "src/a.py"}),
                    json.dumps({"file_change_id": 2, "file_path": "src/b.py"}),
                    json.dumps({"file_change_id": 3, "file_path": "src/c.js"}),
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        return argparse.Namespace(
            function_dataset=function_path,
            cwe_map=cwe_path,
            commit_dataset=commits_path,
            output_dir=root / "processed",
            file_metadata=metadata_path,
            tokenizer="unavailable-test-tokenizer",
            max_tokens=512,
            offline=True,
            allow_approximate_token_count=True,
        )

    def test_commit_normalization_handles_pull_commit_urls(self) -> None:
        value = normalize_commit(
            "https://github.com/acme/app/pull/2/commits/abcdef0123456789/commit/"
            "https://github.com/acme/app/pull/2/commits/abcdef0123456789"
        )
        self.assertEqual(value["repository"], "acme/app")
        self.assertEqual(value["commit_id"], "abcdef0123456789")

    def test_every_row_is_emitted_and_duplicates_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch("scripts.filter_pyvul.TokenCounter", ExactTestTokenCounter):
                records = filter_dataset(self.write_inputs(root))
            self.assertEqual(len(records), 3)
            self.assertEqual(sum(1 for item in records if item["status"] == "REJECTED"), 2)
            self.assertEqual(records[0]["status"], "ACCEPTED")
            self.assertEqual(records[0]["reason_codes"], ["accepted_exact_target_cwe"])
            self.assertIn("rejected_duplicate", records[1]["reason_codes"])
            self.assertIn("rejected_non_python", records[2]["reason_codes"])
            emitted = 0
            for name in ("accepted.jsonl", "manual_review.jsonl", "rejected.jsonl"):
                emitted += len((root / "processed" / name).read_text(encoding="utf-8").splitlines())
            self.assertEqual(emitted, 3)
            self.assertTrue((root / "processed" / "filter_summary.csv").is_file())


if __name__ == "__main__":
    unittest.main()
