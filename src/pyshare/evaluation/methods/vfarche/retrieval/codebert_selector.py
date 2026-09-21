from __future__ import annotations

from pathlib import Path


class MissingCodeBERTCheckpoint(RuntimeError):
    pass


def select_with_codebert(
    description: str,
    funcs: list[dict],
    *,
    checkpoint: str | Path | None,
    top_k: int = 100,
    batch_size: int = 8,
) -> list[dict]:
    """Select PATCH-ABSENT candidates with a fine-tuned CodeBERT checkpoint.

    The VFArCHE paper uses a supervised CodeBERT cross-encoder trained on
    millions of CVE-function pairs. That checkpoint is not present in this repo.
    This adapter deliberately requires an explicit local checkpoint path so the
    project does not silently pretend that base CodeBERT equals the paper model.
    """
    if not checkpoint:
        raise MissingCodeBERTCheckpoint(
            "CodeBERT selector checkpoint is missing. Train or provide the "
            "paper-style fine-tuned checkpoint, then pass its local path."
        )

    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
    except ImportError as exc:
        raise MissingCodeBERTCheckpoint(
            "Install optional dependencies torch and transformers to use the "
            "CodeBERT selector."
        ) from exc

    checkpoint = Path(checkpoint)
    if not checkpoint.exists():
        raise MissingCodeBERTCheckpoint(f"Checkpoint path does not exist: {checkpoint}")

    tokenizer = AutoTokenizer.from_pretrained(str(checkpoint))
    model = AutoModelForSequenceClassification.from_pretrained(str(checkpoint))
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    model.eval()

    scored: list[dict] = []
    with torch.no_grad():
        for start in range(0, len(funcs), batch_size):
            batch = funcs[start : start + batch_size]
            encoded = tokenizer(
                [description] * len(batch),
                [func.get("body") or func.get("source") or "" for func in batch],
                truncation=True,
                max_length=512,
                padding=True,
                return_tensors="pt",
            )
            encoded = {k: v.to(device) for k, v in encoded.items()}
            logits = model(**encoded).logits
            if logits.shape[-1] == 1:
                scores = torch.sigmoid(logits[:, 0]).detach().cpu().tolist()
            else:
                scores = torch.softmax(logits, dim=-1)[:, -1].detach().cpu().tolist()
            for func, score in zip(batch, scores):
                scored.append({**func, "codebert_selector_score": float(score)})

    scored.sort(key=lambda item: item["codebert_selector_score"], reverse=True)
    return scored[:top_k]
