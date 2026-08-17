#!/usr/bin/env python3
"""Train and freeze the lightweight v3 instruction/data-boundary model.

This script deliberately accepts only the opened development sources. The final
BIPIA evaluation files are not read here, which makes the external evaluation a
genuine train/test separation rather than another benchmark-specific patch.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

from agentguard.detectors.contextual_injection import contextual_features


SEED = 20260817
THRESHOLD = 0.70
NOTINJECT_FILES = ("NotInject_one.json", "NotInject_two.json", "NotInject_three.json")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--notinject-dir", type=Path, required=True)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parents[1]
        / "src/agentguard/assets/contextual_injection_v3.json",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "results/v3-training-validation.json",
    )
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def stable_holdout(text: str, modulo: int = 5) -> bool:
    return int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:8], 16) % modulo == 0


def load_rows(project_root: Path, notinject_dir: Path) -> Tuple[List[Tuple[str, int]], dict]:
    attack_path = project_root / "results/injecagent-base-cases.jsonl"
    attacks: Dict[str, int] = {}
    with attack_path.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            if row["label"] == "unsafe":
                attacks[row["external_metadata"]["attacker_instruction"]] = 1

    benign: Dict[str, int] = {}
    source_hashes = {str(attack_path.relative_to(project_root)): sha256(attack_path)}
    for filename in NOTINJECT_FILES:
        path = notinject_dir / filename
        source_hashes[f"PIGuard/datasets/{filename}"] = sha256(path)
        for item in json.loads(path.read_text(encoding="utf-8")):
            benign[item["prompt"]] = 0

    rows = [(text, 1) for text in attacks] + [(text, 0) for text in benign]
    provenance = {
        "positive_source": "InjecAgent attacker_instruction values from opened development conversion",
        "negative_source": "PIGuard NotInject hard-benign prompts",
        "source_hashes_sha256": source_hashes,
        "unique_positive_count": len(attacks),
        "unique_negative_count": len(benign),
        "piguard_commit": "1b5751e88bf7475acbedfc8eda795ce060307c84",
        "licenses": {"InjecAgent": "MIT", "PIGuard": "MIT"},
    }
    return rows, provenance


def build_vocab(rows: Iterable[Tuple[str, int]], min_df: int = 2, max_features: int = 12_000) -> set:
    document_frequency: Counter[str] = Counter()
    for text, _label in rows:
        document_frequency.update(contextual_features(text).keys())
    ranked = sorted(document_frequency.items(), key=lambda item: (-item[1], item[0]))
    return {name for name, count in ranked[:max_features] if count >= min_df}


def vector(text: str, vocabulary: set) -> Dict[str, int]:
    return {
        name: value
        for name, value in contextual_features(text).items()
        if name in vocabulary and value
    }


def sigmoid(value: float) -> float:
    value = max(-30.0, min(30.0, value))
    return 1.0 / (1.0 + math.exp(-value))


def train_model(
    rows: Sequence[Tuple[str, int]], vocabulary: set, *, epochs: int = 80
) -> Tuple[Dict[str, float], float]:
    weights: Dict[str, float] = {}
    positives = sum(label for _text, label in rows)
    negatives = len(rows) - positives
    positive_weight = negatives / max(1, positives)
    bias = math.log((positives + 1) / (negatives + 1))
    indexed = [(vector(text, vocabulary), label) for text, label in rows]
    generator = random.Random(SEED)
    for epoch in range(epochs):
        generator.shuffle(indexed)
        learning_rate = 0.16 / (1.0 + epoch * 0.04)
        for features, label in indexed:
            score = bias + sum(weights.get(name, 0.0) * value for name, value in features.items())
            probability = sigmoid(score)
            importance = positive_weight if label else 1.0
            gradient = (label - probability) * importance
            bias += learning_rate * gradient
            for name, value in features.items():
                current = weights.get(name, 0.0)
                weights[name] = current + learning_rate * (gradient * value - 0.0008 * current)
    return weights, bias


def predict(text: str, vocabulary: set, weights: Dict[str, float], bias: float) -> float:
    features = vector(text, vocabulary)
    return sigmoid(bias + sum(weights.get(name, 0.0) * value for name, value in features.items()))


def metrics(scored: Sequence[Tuple[float, int, str]], threshold: float) -> dict:
    true_positive = false_positive = true_negative = false_negative = 0
    errors = []
    for probability, label, text in scored:
        predicted = probability >= threshold
        if label and predicted:
            true_positive += 1
        elif label:
            false_negative += 1
            errors.append({"label": label, "probability": round(probability, 6), "text": text})
        elif predicted:
            false_positive += 1
            errors.append({"label": label, "probability": round(probability, 6), "text": text})
        else:
            true_negative += 1
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 0.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 0.0
    specificity = true_negative / (true_negative + false_positive) if true_negative + false_positive else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "true_positive": true_positive,
        "false_positive": false_positive,
        "true_negative": true_negative,
        "false_negative": false_negative,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "specificity": round(specificity, 4),
        "f1": round(f1, 4),
        "errors": errors,
    }


def main() -> None:
    args = parse_args()
    rows, provenance = load_rows(args.project_root, args.notinject_dir)
    development = [row for row in rows if not stable_holdout(row[0])]
    validation = [row for row in rows if stable_holdout(row[0])]

    validation_vocab = build_vocab(development)
    validation_weights, validation_bias = train_model(development, validation_vocab)
    scored = [
        (predict(text, validation_vocab, validation_weights, validation_bias), label, text)
        for text, label in validation
    ]
    validation_metrics = metrics(scored, THRESHOLD)

    # Once the development protocol and threshold are fixed, all opened rows are
    # used to fit the deployable model. BIPIA remains unopened by this script.
    final_vocab = build_vocab(rows)
    final_weights, final_bias = train_model(rows, final_vocab)
    metadata = {
        "version": "3.0.0",
        "algorithm": "class-weighted sparse logistic regression",
        "purpose": "instruction-vs-data boundary classification in untrusted tool output",
        "seed": SEED,
        "threshold_selection": (
            "Fixed at 0.70 after opened SHA-256 instruction-level development split; "
            "external BIPIA files were not read during training."
        ),
        "split_rule": "sha256(normalized-source-text) modulo 5 equals 0 => opened validation",
        "feature_family": "binary word/bigram/character-3-to-5-gram plus structural indicators",
        "provenance": provenance,
        "opened_validation_metrics": validation_metrics,
        "opened_development_count": len(development),
        "opened_validation_count": len(validation),
        "final_training_count": len(rows),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "limitations": [
            "Statistical evidence cannot authorize a tool action.",
            "English-dominant development data.",
            "Opened validation is developmental evidence, not external confirmation.",
        ],
    }
    artifact = {
        "format": "agentguard-contextual-linear-v1",
        "threshold": THRESHOLD,
        "bias": round(final_bias, 12),
        "weights": {name: round(final_weights[name], 12) for name in sorted(final_weights)},
        "metadata": metadata,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")

    report = {
        "artifact": str(args.output.relative_to(args.project_root)),
        "artifact_sha256": sha256(args.output),
        "threshold": THRESHOLD,
        "development_count": len(development),
        "validation_count": len(validation),
        "validation_metrics": validation_metrics,
        "provenance": provenance,
        "protocol_note": "BIPIA is reserved for one-time external evaluation after this artifact is frozen.",
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
