from __future__ import annotations

import argparse
import json
import random
from pathlib import Path


def _read_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


class PairDataset:
    def __init__(self, rows: list[dict], tokenizer, max_length: int) -> None:
        self.rows = rows
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self) -> int:
        return len(self.rows)

    def __getitem__(self, idx: int) -> dict:
        row = self.rows[idx]
        encoded = self.tokenizer(
            row["description"],
            row.get("source") or "",
            truncation=True,
            max_length=self.max_length,
        )
        encoded["labels"] = int(row["label"])
        return encoded


def _split(rows: list[dict], validation_ratio: float, seed: int) -> tuple[list[dict], list[dict]]:
    rows = rows[:]
    random.Random(seed).shuffle(rows)
    n_val = max(1, int(len(rows) * validation_ratio)) if len(rows) > 1 else 0
    return rows[n_val:], rows[:n_val]


def main() -> None:
    ap = argparse.ArgumentParser(description="Fine-tune CodeBERT for PATCH-ABSENT candidate selection.")
    ap.add_argument("--train", required=True, type=Path, help="Training JSONL from build_codebert_training_data.")
    ap.add_argument("--validation", type=Path, help="Optional validation JSONL.")
    ap.add_argument("--out", required=True, type=Path, help="Checkpoint output directory.")
    ap.add_argument("--base-model", default="microsoft/codebert-base")
    ap.add_argument("--max-length", type=int, default=512)
    ap.add_argument("--epochs", type=float, default=2.0)
    ap.add_argument("--batch-size", type=int, default=8)
    ap.add_argument("--learning-rate", type=float, default=2e-5)
    ap.add_argument("--validation-ratio", type=float, default=0.1)
    ap.add_argument("--seed", type=int, default=13)
    args = ap.parse_args()

    try:
        import numpy as np
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            DataCollatorWithPadding,
            Trainer,
            TrainingArguments,
        )
    except ImportError as exc:
        raise SystemExit(
            "Install CodeBERT training dependencies first: "
            "pip install -r configs/evaluation/requirements/vfarche-codebert.txt"
        ) from exc

    rows = _read_jsonl(args.train)
    if args.validation:
        train_rows, val_rows = rows, _read_jsonl(args.validation)
    else:
        train_rows, val_rows = _split(rows, args.validation_ratio, args.seed)

    tokenizer = AutoTokenizer.from_pretrained(args.base_model)
    model = AutoModelForSequenceClassification.from_pretrained(args.base_model, num_labels=2)
    train_ds = PairDataset(train_rows, tokenizer, args.max_length)
    val_ds = PairDataset(val_rows, tokenizer, args.max_length) if val_rows else None

    def compute_metrics(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        return {"accuracy": float((preds == labels).mean())}

    kwargs = {
        "output_dir": str(args.out),
        "num_train_epochs": args.epochs,
        "per_device_train_batch_size": args.batch_size,
        "per_device_eval_batch_size": args.batch_size,
        "learning_rate": args.learning_rate,
        "weight_decay": 0.01,
        "save_strategy": "epoch",
        "logging_steps": 50,
        "seed": args.seed,
        "report_to": [],
    }
    if val_ds:
        kwargs["evaluation_strategy"] = "epoch"
        kwargs["load_best_model_at_end"] = True
        kwargs["metric_for_best_model"] = "accuracy"

    training_args = TrainingArguments(**kwargs)
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        tokenizer=tokenizer,
        data_collator=DataCollatorWithPadding(tokenizer),
        compute_metrics=compute_metrics if val_ds else None,
    )
    trainer.train()
    trainer.save_model(str(args.out))
    tokenizer.save_pretrained(str(args.out))
    print(f"[train-codebert] saved checkpoint -> {args.out}")


if __name__ == "__main__":
    main()
