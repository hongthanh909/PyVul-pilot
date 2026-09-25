# Pilot dataset: five CWE classes + SAFE (v1)

This is a fixed split of `../model-dataset/all_samples.jsonl` for the first
CodeBERT pilot. It includes CWE-22, CWE-78, CWE-79, CWE-89, CWE-287, and
SAFE. CWE-798 is deliberately excluded until there are enough independent
cases to split it across train, validation, and test.

- Source rows: 443; included: 437; excluded CWE-798 rows: 6.
- Split: train 317, validation 68, test 52.
- Split unit: repository + fix commit; seed: 42; no commit group crosses splits.
- Source SHA-256: `EBE6147D178C1FF31409A614A56071569FCEAF49E06B7393CE517B9637961FD3`.
- `label_map.json` fixes the class ID order for this version.
- `split_summary.csv` records per-label row, commit-group, and repository counts.

Regenerate this version with:

```powershell
python scripts\prepare_smoke_test.py --input data\model-dataset\all_samples.jsonl --output-dir data\pilot-5cwe-v1
```

Only regenerate deliberately: subsequent changes to the source dataset can
alter the split and make pilot results incomparable with this version.
