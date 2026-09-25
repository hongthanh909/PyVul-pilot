#!/usr/bin/env python3
"""Run a small, reproducible CodeBERT sequence-classification smoke test."""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import random
import shutil
from collections import Counter
from pathlib import Path
from typing import Any, Mapping, Sequence


def require_training_dependencies():
    try:
        import torch
        from torch.utils.data import DataLoader, Dataset
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ImportError as exc:
        raise SystemExit(
            "Missing training dependencies. Activate .venv and run: "
            "python -m pip install -r requirements-training.txt"
        ) from exc
    return torch, DataLoader, Dataset, AutoModelForSequenceClassification, AutoTokenizer


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"Expected object at {path}:{line_number}")
            rows.append(value)
    if not rows:
        raise ValueError(f"No rows in {path}")
    return rows


def stratified_limit(rows: Sequence[dict[str, Any]], limit: int, seed: int) -> list[dict[str, Any]]:
    if limit <= 0 or len(rows) <= limit:
        return list(rows)
    by_label: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        by_label.setdefault(int(row["label_id"]), []).append(row)
    rng = random.Random(seed)
    for values in by_label.values():
        rng.shuffle(values)
    selected: list[dict[str, Any]] = []
    labels = sorted(by_label)
    while len(selected) < limit and labels:
        remaining: list[int] = []
        for label in labels:
            values = by_label[label]
            if values and len(selected) < limit:
                selected.append(values.pop())
            if values:
                remaining.append(label)
        labels = remaining
    rng.shuffle(selected)
    return selected


def classification_metrics(
    truth: Sequence[int], predictions: Sequence[int], label_count: int
) -> dict[str, Any]:
    correct = sum(a == b for a, b in zip(truth, predictions))
    per_label: dict[str, dict[str, float | int]] = {}
    f1_values: list[float] = []
    for label in range(label_count):
        tp = sum(a == label and b == label for a, b in zip(truth, predictions))
        fp = sum(a != label and b == label for a, b in zip(truth, predictions))
        fn = sum(a == label and b != label for a, b in zip(truth, predictions))
        support = sum(a == label for a in truth)
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        f1_values.append(f1)
        per_label[str(label)] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "support": support,
        }
    return {
        "accuracy": correct / len(truth) if truth else 0.0,
        "macro_f1": sum(f1_values) / label_count if label_count else 0.0,
        "samples": len(truth),
        "per_label": per_label,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=Path, default=Path("data/smoke-test"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/codebert-smoke"))
    parser.add_argument("--model", default="microsoft/codebert-base")
    parser.add_argument("--epochs", type=int, default=1)
    parser.add_argument("--batch-size", type=int, default=4)
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--learning-rate", type=float, default=2e-5)
    parser.add_argument("--max-train-samples", type=int, default=96)
    parser.add_argument("--max-eval-samples", type=int, default=60)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--cpu", action="store_true")
    args = parser.parse_args(argv)
    if args.epochs < 1 or args.batch_size < 1 or args.max_length < 2:
        raise ValueError("epochs, batch-size and max-length must be positive")

    torch, DataLoader, Dataset, AutoModel, AutoTokenizer = require_training_dependencies()
    random.seed(args.seed)
    torch.manual_seed(args.seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(args.seed)

    label_map = json.loads((args.data_dir / "label_map.json").read_text(encoding="utf-8-sig"))
    if not isinstance(label_map, dict) or not label_map:
        raise ValueError("label_map.json must contain a non-empty object")
    id_to_label = {int(value): str(key) for key, value in label_map.items()}
    train_rows = stratified_limit(
        read_jsonl(args.data_dir / "train.jsonl"), args.max_train_samples, args.seed
    )
    validation_rows = stratified_limit(
        read_jsonl(args.data_dir / "validation.jsonl"), args.max_eval_samples, args.seed + 1
    )
    test_rows = stratified_limit(
        read_jsonl(args.data_dir / "test.jsonl"), args.max_eval_samples, args.seed + 2
    )

    class CodeDataset(Dataset):
        def __init__(self, rows):
            self.rows = rows

        def __len__(self):
            return len(self.rows)

        def __getitem__(self, index):
            return self.rows[index]

    tokenizer = AutoTokenizer.from_pretrained(args.model, local_files_only=args.offline)
    model = AutoModel.from_pretrained(
        args.model,
        num_labels=len(label_map),
        id2label=id_to_label,
        label2id={str(key): int(value) for key, value in label_map.items()},
        local_files_only=args.offline,
    )
    device = torch.device("cpu" if args.cpu or not torch.cuda.is_available() else "cuda")
    model.to(device)

    def collate(batch):
        encoded = tokenizer(
            [str(row["code"]) for row in batch],
            padding=True,
            truncation=True,
            max_length=args.max_length,
            return_tensors="pt",
        )
        encoded["labels"] = torch.tensor([int(row["label_id"]) for row in batch], dtype=torch.long)
        encoded["sample_ids"] = [str(row["model_sample_id"]) for row in batch]
        return encoded

    generator = torch.Generator().manual_seed(args.seed)
    train_loader = DataLoader(
        CodeDataset(train_rows),
        batch_size=args.batch_size,
        shuffle=True,
        generator=generator,
        collate_fn=collate,
    )
    validation_loader = DataLoader(
        CodeDataset(validation_rows), batch_size=args.batch_size, shuffle=False, collate_fn=collate
    )
    test_loader = DataLoader(
        CodeDataset(test_rows), batch_size=args.batch_size, shuffle=False, collate_fn=collate
    )

    counts = Counter(int(row["label_id"]) for row in train_rows)
    weights = [len(train_rows) / (len(label_map) * max(counts.get(index, 0), 1)) for index in range(len(label_map))]
    criterion = torch.nn.CrossEntropyLoss(weight=torch.tensor(weights, dtype=torch.float, device=device))
    optimizer = torch.optim.AdamW(model.parameters(), lr=args.learning_rate)

    def evaluate(loader):
        model.eval()
        truth: list[int] = []
        predicted: list[int] = []
        sample_ids: list[str] = []
        total_loss = 0.0
        with torch.no_grad():
            for batch in loader:
                labels = batch.pop("labels").to(device)
                ids = batch.pop("sample_ids")
                inputs = {key: value.to(device) for key, value in batch.items()}
                logits = model(**inputs).logits
                total_loss += float(criterion(logits, labels).item())
                truth.extend(labels.cpu().tolist())
                predicted.extend(logits.argmax(dim=-1).cpu().tolist())
                sample_ids.extend(ids)
        metrics = classification_metrics(truth, predicted, len(label_map))
        metrics["loss"] = total_loss / max(len(loader), 1)
        return metrics, list(zip(sample_ids, truth, predicted))

    history: list[dict[str, Any]] = []
    for epoch in range(1, args.epochs + 1):
        model.train()
        total_loss = 0.0
        for step, batch in enumerate(train_loader, 1):
            labels = batch.pop("labels").to(device)
            batch.pop("sample_ids")
            inputs = {key: value.to(device) for key, value in batch.items()}
            optimizer.zero_grad(set_to_none=True)
            logits = model(**inputs).logits
            loss = criterion(logits, labels)
            if not math.isfinite(float(loss.item())):
                raise RuntimeError(f"Non-finite loss at epoch={epoch}, step={step}: {loss.item()}")
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            total_loss += float(loss.item())
            if step == 1 or step % 10 == 0 or step == len(train_loader):
                print(f"epoch={epoch} step={step}/{len(train_loader)} loss={loss.item():.4f}")
        validation_metrics, _ = evaluate(validation_loader)
        history.append(
            {
                "epoch": epoch,
                "train_loss": total_loss / max(len(train_loader), 1),
                "validation_loss": validation_metrics["loss"],
                "validation_accuracy": validation_metrics["accuracy"],
                "validation_macro_f1": validation_metrics["macro_f1"],
            }
        )
        print(
            f"validation: loss={validation_metrics['loss']:.4f} "
            f"accuracy={validation_metrics['accuracy']:.4f} "
            f"macro_f1={validation_metrics['macro_f1']:.4f}"
        )

    validation_metrics, _ = evaluate(validation_loader)
    test_metrics, test_predictions = evaluate(test_loader)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_dir = args.output_dir / "checkpoint"
    model.save_pretrained(checkpoint_dir)
    tokenizer.save_pretrained(checkpoint_dir)
    shutil.copy2(args.data_dir / "label_map.json", args.output_dir / "label_map.json")
    metrics = {
        "model": args.model,
        "device": str(device),
        "seed": args.seed,
        "train_samples": len(train_rows),
        "validation_samples": len(validation_rows),
        "test_samples": len(test_rows),
        "validation": validation_metrics,
        "test": test_metrics,
    }
    (args.output_dir / "metrics.json").write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    with (args.output_dir / "training_log.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(history[0]))
        writer.writeheader()
        writer.writerows(history)
    with (args.output_dir / "predictions.jsonl").open("w", encoding="utf-8", newline="\n") as handle:
        for sample_id, truth, predicted in test_predictions:
            handle.write(
                json.dumps(
                    {
                        "model_sample_id": sample_id,
                        "true_label_id": truth,
                        "true_label": id_to_label[truth],
                        "predicted_label_id": predicted,
                        "predicted_label": id_to_label[predicted],
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
    print(f"Smoke test complete on {device}. Outputs: {args.output_dir.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
