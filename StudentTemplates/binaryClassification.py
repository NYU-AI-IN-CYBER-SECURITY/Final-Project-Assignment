"""
binaryClassification.py - Task: binary classification

Predict, for every packet, whether it is normal (0) or an attack (1), the same meaning as the `label` column in the labelled data. main.py turns the prediction into an action: 0 -> PERMIT, 1 -> DROP.
Any approach is allowed.

Contract (checked by main.py):
  classify_binary(packets, context) returns a DataFrame with exactly one row
  per input packet and these columns:
      packet_id          copied from the input
      binary_pred        int, 0 (normal) or 1 (attack)
      binary_confidence  float in [0, 1] for each prediction, or NaN if you have none

The CSV passed at grading time has NO `label`, `attack_cat` or `verdict` column.

`context` is shared by all modules (see warmUp.py). context["stage_results"] holds the validated outputs of the stages that already ran, keyed by "policy", "binary" and "multiclass".

Run this module on its own (checks the output against the contract above, and prints accuracy, precision, recall and F1 if the CSV has a `label` column):
    python binaryClassification.py --input labelled.csv --policies policy.yaml
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

# Folder of your submission. Trained models are saved here, next to the template files.
# Load this task's model files by their uploaded names, e.g. MODELS_DIR / "abc123_binaryClassification_rf.onnx".
# If your approach uses trained models, see the rules in warmUp.py.
SUBMISSION_DIR = Path(__file__).parent
MODELS_DIR = SUBMISSION_DIR


def classify_binary(packets: pd.DataFrame, context: dict) -> pd.DataFrame:
    """Return one row per packet with a 0/1 prediction and a confidence."""

    # TODO: implement binary classification. Placeholder: every packet is normal.
    preds = np.zeros(len(packets), dtype=int)
    confidence = np.full(len(packets), np.nan)

    return pd.DataFrame({
        "packet_id": packets["packet_id"].to_numpy(),
        "binary_pred": preds,
        "binary_confidence": confidence,
    })


if __name__ == "__main__":
    import checkPolicy
    import main
    import warmUp

    parser = argparse.ArgumentParser(description="Run binary classification on its own")
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
    data = data.rename(columns={"Label": "label"})
    truth = data.pop("label") if "label" in data.columns else None
    data = data.drop(columns=["attack_cat", "verdict", "packet_id"], errors="ignore")
    data.insert(0, "packet_id", np.arange(len(data)))
    context = warmUp.warm_up({"policies": checkPolicy.load_policies(args.policies)})
    context.setdefault("stage_results", {})
    out = classify_binary(data, context)
    # The same check main.py runs: stops with an error if the output breaks the contract.
    out = main.validate_stage_output("binary", out, data["packet_id"])
    out = out.sort_values("packet_id")
    print(out["binary_pred"].value_counts().to_string())
    if truth is not None:
        truth_labels = truth.astype(int).astype(str).tolist()
        predicted_labels = out["binary_pred"].astype(str).tolist()
        print_scores(truth_labels, predicted_labels, [("Normal (0)", ["0"]), ("Attack (1)", ["1"])])
        print("These task scores are for your own diagnosis. Grading scores only each packet's final action.")
