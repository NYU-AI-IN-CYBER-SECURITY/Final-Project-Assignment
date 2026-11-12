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

Run this module on its own (checks the output against the contract above, and prints accuracy if the CSV has an `attack_cat` column):
    python multiClassClassification.py --input labelled.csv --policies policy.yaml
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

# Folder of your submission. Trained models are saved here, next to the template files.
# Load this task's model by its uploaded name, e.g. MODELS_DIR / "abc123_multiClassClassification.onnx".
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
        accuracy = (out["attack_cat_pred"].to_numpy() == truth.to_numpy()).mean()
        print(f"accuracy: {accuracy:.4f}")
