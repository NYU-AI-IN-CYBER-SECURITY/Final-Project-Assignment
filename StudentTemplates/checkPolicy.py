"""
checkPolicy.py - Task: policy checking

Decide, for every packet, whether it violates any of the given policies.
A violating packet is DENIED, and DENY overrides the classification results.
The policies are provided separately as a document.
Any approach is allowed.

Contract (checked by main.py):
  check_policy(packets, context) returns a DataFrame with exactly one row per
  input packet and these columns:
      packet_id        copied from the input
      policy_decision  "DENY" or "ALLOW"
      violated_policy  id(s) of the violated policies, ";"-separated, "" if none
      policy_reason    short human-readable reason, "" if none

`context` is shared by all modules (see warmUp.py). context["stage_results"] holds the validated outputs of the stages that already ran, keyed by "policy", "binary" and "multiclass".

Run this module on its own (checks the output against the contract above):
    python checkPolicy.py --input packets.csv --policies policy.yaml
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

# Folder of your submission. Trained models are saved here, next to the template files.
# Load this task's model by its uploaded name, e.g. MODELS_DIR / "abc123_checkPolicy.onnx".
# If your approach uses trained models, see the rules in warmUp.py.
SUBMISSION_DIR = Path(__file__).parent
MODELS_DIR = SUBMISSION_DIR


def load_policies(policy_path: Path):
    """Read the policy document. main.py calls this once; the return value is available to every module as context["policies"].

    The default returns the raw text. You may return any other representation that suits your approach.
    """
    return Path(policy_path).read_text(encoding="utf-8")


def check_policy(packets: pd.DataFrame, context: dict) -> pd.DataFrame:
    """Return one row per packet saying whether it violates any policy."""
    policies = context["policies"]  # noqa: F841  (use it in your implementation)

    result = pd.DataFrame({
        "packet_id": packets["packet_id"].to_numpy(),
        "policy_decision": "ALLOW",
        "violated_policy": "",
        "policy_reason": "",
    })

    # TODO: implement policy checking. Placeholder: every packet is allowed.
    # The helper flag_violation() below records a violation for you.

    return result


def flag_violation(result: pd.DataFrame, mask, policy_id: str, reason: str) -> None:
    """Optional helper: mark the packets selected by `mask` (True/False per row, in the same order as `packets`) as DENY under `policy_id`.

    A packet that violates several policies keeps every id and reason, ";"-separated.
    """
    mask = pd.Series(mask).fillna(False).to_numpy(dtype=bool)
    result.loc[mask, "policy_decision"] = "DENY"
    for col, value in (("violated_policy", policy_id), ("policy_reason", reason)):
        current = result.loc[mask, col]
        result.loc[mask, col] = np.where(current == "", value, current + ";" + value)


if __name__ == "__main__":
    import main
    import warmUp

    parser = argparse.ArgumentParser(description="Run policy checking on its own")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--policies", required=True, type=Path)
    args = parser.parse_args()

    data = pd.read_csv(args.input, low_memory=False)
    data.columns = data.columns.str.strip()
    data = data.drop(columns=["label", "Label", "attack_cat", "verdict", "packet_id"], errors="ignore")
    data.insert(0, "packet_id", np.arange(len(data)))
    context = warmUp.warm_up({"policies": load_policies(args.policies)})
    context.setdefault("stage_results", {})
    out = check_policy(data, context)
    # The same check main.py runs: stops with an error if the output breaks the contract.
    out = main.validate_stage_output("policy", out, data["packet_id"])
    print(out["policy_decision"].value_counts().to_string())
    print(out.loc[out["policy_decision"] == "DENY"].head(10).to_string(index=False))
