# PyVul dataset filter

`scripts/filter_pyvul.py` implements the project criteria for the six target
CWEs under OWASP Top 10:2025. Every non-empty input line is written to exactly
one status file with one or more `reason_codes`.

## Run with the exact CodeBERT tokenizer

```powershell
python -m pip install -r requirements-filter.txt
python scripts/filter_pyvul.py
```

The outputs are written to `data/processed/`:

- `accepted.jsonl`
- `manual_review.jsonl`
- `rejected.jsonl`
- `filter_summary.csv`

The first run can download `microsoft/codebert-base`. Use `--offline` only when
that tokenizer is already cached. The option `--allow-approximate-token-count`
exists for smoke tests; every otherwise valid approximate-count record is kept
out of `ACCEPTED` with `manual_review_tokenizer_unavailable`.

## Important limitation of the published files

The provided `dataset/function_level_dataset.out` contains `file_change_id` but
does not contain a file path. Since file path is required by the criteria, these
records are conservatively assigned `MANUAL_REVIEW` with
`manual_review_missing_provenance` until metadata is supplied.

Supply a JSONL enrichment file keyed by `file_change_id`:

```json
{"file_change_id": 123456, "file_path": "src/example.py"}
```

Then run:

```powershell
python scripts/filter_pyvul.py --file-metadata dataset/file_metadata.jsonl
```

The enrichment file may use `file_path`, `filename`, `old_path`, or `new_path`.
No source dataset file is modified.

## Recover the missing paths

The released PyVul function-level file drops paths that existed earlier in the
collection pipeline. Recover high-confidence paths from fixing-commit diffs:

```powershell
python scripts/recover_file_paths.py
```

The command is resumable because downloaded diffs are cached under
`data/recovery/cache/`. It writes:

- `dataset/file_metadata.jsonl` for unique high-confidence matches;
- `data/recovery/unresolved_file_paths.csv` for ambiguous/failed matches;
- `data/recovery/recovery_summary.csv` for recovery statistics.

It defaults to Python records in the six target CWEs. Original dataset files are
not modified. Then create a separate filtered result for comparison:

```powershell
python scripts/filter_pyvul.py `
  --file-metadata dataset/file_metadata.jsonl `
  --output-dir data/processed-with-path
```

## Prepare long functions for CodeBERT

This post-filtering step reads only `manual_review.jsonl`. It processes a record
only when `manual_review_long_code` is its sole reason; accepted and rejected
outputs are not touched. Long functions are split with the exact CodeBERT
tokenizer, a 512-token limit (including special tokens), and a 128-token overlap.

```powershell
python scripts/prepare_codebert_chunks.py `
  --input data/processed-with-path/manual_review.jsonl `
  --output-dir data/codebert-ready `
  --max-tokens 512 `
  --stride 128 `
  --offline
```

The script writes all long-function chunks, patch-overlapping training chunks,
the remaining manual-review records, and a CSV summary. It never overwrites the
source manual-review file.

## Supplement external advisory data

External sources first use the canonical function-pair contract in
`schemas/function_pair.schema.json`. Discovery output is an inventory only and
is never treated as training data. The extractor derives the label from each
candidate's `target_cwe`; it must not hard-code a CWE. Small curated batches
may set `include_functions` so unrelated functions changed by the same commit
are recorded in `extraction_review.jsonl` instead of being mislabeled:

```powershell
python scripts/discover_cwe_candidates.py --cwe 798 --ecosystem pip --output-dir data/supplement/cwe-798
python scripts/extract_github_function_pairs.py
python scripts/filter_normalized_pairs.py --offline
```

Each CWE pipeline stores candidate advisories, cached public commit data,
normalized function pairs, extraction review records, and filtered outputs
under `data/supplement/cwe-*/`. A batch remains staged until schema, provenance,
semantic relevance, AST, token length, duplicate, and label-conflict checks
pass. Only then may its accepted output be supplied to
`build_codebert_dataset.py`. Only a long-only manual record may enter the
chunking step; other manual reasons still require human validation.

CWE-798 also supports a curated `module_block` when a credential is assigned
at module scope rather than inside a function. A candidate must explicitly
name the binding in `include_module_bindings`; the extractor keeps that
assignment and its directly referenced top-level definitions, with source
line spans. The filter checks that the named binding itself loses its literal
credential (including an unsafe `os.environ.get` default). This extension is
not enabled for other CWEs. Older records without `unit_type` remain functions.
For example, the Crawl4AI batch lives under
`data/supplement/cwe-798/batches/crawl4ai-cve-2026-56265/`.

## Build the canonical CodeBERT input

`schemas/model_sample.schema.json` defines one uniform row for complete
functions, curated module blocks, and patch-aware chunks. Build the combined,
not-yet-split dataset:

```powershell
python scripts/build_codebert_dataset.py
```

Outputs are written under `data/model-dataset/`. Exact duplicates, label
conflicts, and invalid samples are written separately and excluded from
`all_samples.jsonl`. Train/validation/test splitting must later group by
`group_id` (and preferably repository) so before/after variants and chunks of
one parent function cannot leak across splits.
