import unittest

from scripts.prepare_codebert_chunks import (
    PatchRegion,
    find_patch_regions,
    process_records,
    select_nonredundant_patch_chunks,
    validate_result,
)


class CharacterTokenizer:
    """Small fast-tokenizer stand-in: one non-newline character per token."""

    is_fast = True

    def num_special_tokens_to_add(self, pair=False):
        return 2

    def encode(self, text, add_special_tokens=True, truncation=False):
        ids = [ord(char) for char in text if char != "\n"]
        return ([0] + ids + [2]) if add_special_tokens else ids

    def __call__(
        self,
        text,
        *,
        add_special_tokens=True,
        truncation=False,
        max_length=None,
        stride=0,
        return_overflowing_tokens=False,
        return_offsets_mapping=False,
        padding=False,
    ):
        positions = [(index, index + 1) for index, char in enumerate(text) if char != "\n"]
        capacity = max_length - 2 if add_special_tokens and max_length else len(positions)
        step = capacity - stride if return_overflowing_tokens else capacity
        windows = []
        start = 0
        while start < len(positions) or (not windows and not positions):
            content = positions[start : start + capacity]
            offsets = ([(0, 0)] + content + [(0, 0)]) if add_special_tokens else content
            ids = list(range(len(offsets)))
            windows.append((ids, offsets))
            if not return_overflowing_tokens or start + capacity >= len(positions):
                break
            start += step
        if return_overflowing_tokens:
            return {
                "input_ids": [item[0] for item in windows],
                "offset_mapping": [item[1] for item in windows],
            }
        return {"input_ids": windows[0][0], "offset_mapping": windows[0][1]}


def sample(reason_codes=None, code_after=None):
    before = "def run(value):\n    unsafe_call(value)\n    return value\n"
    after = code_after or "def run(value):\n    safe_call(value)\n    return value\n"
    return {
        "sample_id": "PYVUL_CWE78_000001",
        "source_line": 1,
        "pair_id": "pair-1",
        "repository": "owner/repo",
        "commit": "abc",
        "file_path": "src/run.py",
        "function_name": "run",
        "language": "Python",
        "cwes": ["CWE-78"],
        "labels": ["COMMAND_INJECTION"],
        "owasp_2025": ["A05"],
        "code_before": before,
        "code_after": after,
        "has_paired_negative": True,
        "status": "MANUAL_REVIEW",
        "reason_codes": reason_codes or ["manual_review_long_code"],
    }


class PrepareCodeBertChunksTests(unittest.TestCase):
    def test_patch_regions_include_replaced_line(self):
        record = sample()
        before, after = find_patch_regions(record["code_before"], record["code_after"])
        self.assertEqual(len(before), 1)
        self.assertEqual(len(after), 1)
        self.assertEqual(before[0].line_start, 2)
        self.assertEqual(after[0].line_start, 2)

    def test_long_only_record_creates_bounded_patch_chunks(self):
        tokenizer = CharacterTokenizer()
        result = process_records(
            [sample()],
            tokenizer,
            tokenizer_name="test-tokenizer",
            max_tokens=20,
            stride=5,
        )
        validate_result(result, 20)
        self.assertEqual(len(result.remaining_manual), 0)
        self.assertTrue(result.training_chunks)
        self.assertTrue(all(item["chunk_token_count"] <= 20 for item in result.all_chunks))
        self.assertTrue(all(item["contains_patch"] for item in result.training_chunks))
        self.assertEqual({item["variant"] for item in result.training_chunks}, {"before", "after"})

    def test_redundant_overlapping_patch_chunks_are_not_used_for_training(self):
        chunks = [
            {
                "chunk_index": 1,
                "char_start": 0,
                "char_end": 40,
                "eligible_for_training": True,
                "chunk_status": "MODEL_READY",
                "chunk_reason_codes": ["accepted_chunk_contains_patch"],
            },
            {
                "chunk_index": 2,
                "char_start": 10,
                "char_end": 35,
                "eligible_for_training": True,
                "chunk_status": "MODEL_READY",
                "chunk_reason_codes": ["accepted_chunk_contains_patch"],
            },
        ]
        selected = select_nonredundant_patch_chunks(
            chunks, [PatchRegion(20, 30, 2, 2)]
        )
        self.assertEqual(selected, [chunks[0]])
        self.assertFalse(chunks[1]["eligible_for_training"])
        self.assertEqual(
            chunks[1]["chunk_reason_codes"], ["context_redundant_patch_chunk"]
        )

    def test_record_with_other_reason_stays_manual(self):
        result = process_records(
            [sample(["manual_review_long_code", "manual_review_ast_error"])],
            CharacterTokenizer(),
            tokenizer_name="test-tokenizer",
            max_tokens=20,
            stride=5,
        )
        self.assertFalse(result.all_chunks)
        self.assertEqual(len(result.remaining_manual), 1)
        self.assertEqual(
            result.remaining_manual[0]["chunking_reason_codes"],
            ["manual_review_chunk_other_reasons"],
        )

    def test_missing_pair_stays_manual(self):
        record = sample()
        record["code_after"] = None
        result = process_records(
            [record],
            CharacterTokenizer(),
            tokenizer_name="test-tokenizer",
            max_tokens=20,
            stride=5,
        )
        self.assertFalse(result.all_chunks)
        self.assertEqual(
            result.remaining_manual[0]["chunking_reason_codes"],
            ["manual_review_chunk_missing_pair"],
        )


if __name__ == "__main__":
    unittest.main()
