"""
multiClassClassification.py - Task: multi-class classification

Predict, for every packet, its attack category, the same meaning as the `attack_cat` column in the labelled data.
main.py turns the prediction into an
action: "Normal" -> PERMIT, any attack category -> DROP.
Any approach is allowed.

DoS has been removed as a category for the final project (see the README).

Contract (checked by main.py):
  classify_multiclass(packets, context) returns a DataFrame with exactly one
  row per input packet and these columns:
      packet_id              copied from the input
      attack_cat_pred        one of ATTACK_CATEGORIES (exact spelling)
      multiclass_confidence  float in [0, 1] for each prediction, or NaN if you have none

The CSV passed at grading time has NO `label`, `attack_cat` or `verdict` column.

`context` is shared by all modules (see warmUp.py). context["stage_results"] holds the validated outputs of the stages that already ran, keyed by "policy", "binary" and "multiclass".

Run this module on its own (checks the output against the contract above, and prints accuracy, precision, recall and F1 if the CSV has an `attack_cat` column):
    python multiClassClassification.py --input labelled.csv --policies policy.yaml
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

# Folder of your submission. Trained models are saved here, next to the template files.
# Load this task's model files by their uploaded names, e.g. MODELS_DIR / "abc123_multiClassClassification_rf.onnx".
# If your approach uses trained models, see the rules in warmUp.py.
SUBMISSION_DIR = Path(__file__).parent
MODELS_DIR = SUBMISSION_DIR

# Do not change: predictions must use exactly these names. DoS is not a category in this project.
ATTACK_CATEGORIES = ("Normal", "Generic", "Exploits", "Fuzzers", "Reconnaissance", "Analysis", "Backdoor", "Shellcode", "Worms")


def normalise_attack_cat(values: pd.Series) -> pd.Series:
    """Clean `attack_cat` values from the labelled data so they match
    ATTACK_CATEGORIES: strip spaces, empty -> "Normal", "Backdoors" -> "Backdoor"."""
    cleaned = values.fillna("Normal").astype(str).str.strip()
    return cleaned.replace({"": "Normal", "Backdoors": "Backdoor"})


def classify_multiclass(packets: pd.DataFrame, context: dict) -> pd.DataFrame:
    """Return one row per packet with a predicted category and a confidence."""

    # TODO: implement multi-class classification. Placeholder: every packet is Normal.
    preds = np.full(len(packets), "Normal", dtype=object)
    confidence = np.full(len(packets), np.nan)

    return pd.DataFrame({
        "packet_id": packets["packet_id"].to_numpy(),
        "attack_cat_pred": preds,
        "multiclass_confidence": confidence,
    })


if __name__ == "__main__":
    import checkPolicy
    import main
    import warmUp

    parser = argparse.ArgumentParser(description="Run multi-class classification on its own")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--policies", required=True, type=Path)
    args = parser.parse_args()

    def scores(truth, predicted, focus_classes):
        """Precision, recall and F1, averaged over focus_classes, computed as the grader does.

        A 0/0 ratio counts as 0, e.g. precision for a class that is never predicted.
        """
        precisions, recalls, f1s = [], [], []
        for focus in focus_classes:
            true_positives = sum(t == focus and p == focus for t, p in zip(truth, predicted))
            predicted_count = sum(p == focus for p in predicted)
            actual_count = sum(t == focus for t in truth)
            precision = true_positives / predicted_count if predicted_count else 0.0
            recall = true_positives / actual_count if actual_count else 0.0
            precisions.append(precision)
            recalls.append(recall)
            f1s.append(2 * precision * recall / (precision + recall) if precision + recall else 0.0)
        count = len(focus_classes) or 1
        return sum(precisions) / count, sum(recalls) / count, sum(f1s) / count

    def print_scores(truth, predicted, rows):
        """Print accuracy, then precision, recall and F1 for each (name, focus classes) row."""
        accuracy = sum(t == p for t, p in zip(truth, predicted)) / len(truth) if truth else 0.0
        print(f"accuracy: {accuracy:.4f}")
        for name, focus_classes in rows:
            precision, recall, f1 = scores(truth, predicted, focus_classes)
            print(f"{name:<24} precision {precision:.4f}   recall {recall:.4f}   F1 {f1:.4f}")

    data = pd.read_csv(args.input, low_memory=False)
    data.columns = data.columns.str.strip()
    truth = normalise_attack_cat(data.pop("attack_cat")) if "attack_cat" in data.columns else None
    data = data.drop(columns=["label", "Label", "verdict", "packet_id"], errors="ignore")
    data.insert(0, "packet_id", np.arange(len(data)))
    context = warmUp.warm_up({"policies": checkPolicy.load_policies(args.policies)})
    context.setdefault("stage_results", {})
    out = classify_multiclass(data, context)
    # The same check main.py runs: stops with an error if the output breaks the contract.
    out = main.validate_stage_output("multiclass", out, data["packet_id"])
    out = out.sort_values("packet_id")
    print(out["attack_cat_pred"].value_counts().to_string())
    if truth is not None:
        truth_labels = truth.tolist()
        predicted_labels = out["attack_cat_pred"].tolist()
        attack_classes = sorted({label for label in truth_labels if label != "Normal"})
        rows = [("Normal", ["Normal"])]
        if attack_classes:
            rows.append(("Attack (macro average)", attack_classes))
        rows += [(f"  {category}", [category]) for category in ATTACK_CATEGORIES[1:] if category in attack_classes]
        print_scores(truth_labels, predicted_labels, rows)
        print("These task scores are for your own diagnosis. Grading scores only each packet's final action.")
