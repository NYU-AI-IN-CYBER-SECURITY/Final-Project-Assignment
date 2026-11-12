"""
generateIOCReport.py - Task: IOC report

Generate the IOC report from the results of policy checking and both classifications. 
The required report format is described in the assignment README, under "IOC report format".
Write one .json file holding a JSON array, with one entry per DROP or DENY packet.

main.py calls generate_report() once, after all three stages, with `results`:
one row per packet, sorted by packet_id, with these columns:

    packet_id                        0..N-1 in input-file order
    <all original input columns>     (no `label`, `attack_cat` or `verdict`)
    policy_decision                  "DENY" / "ALLOW"
    violated_policy, policy_reason   ";"-separated, "" if none
    binary_pred                      0 / 1   (missing if the stage skipped the packet)
    binary_confidence                [0, 1] or NaN
    binary_action                    "PERMIT" / "DROP" / ""
    attack_cat_pred                  attack category (missing if skipped)
    multiclass_confidence            [0, 1] or NaN
    multiclass_action                "PERMIT" / "DROP" / ""
    final_action                     "DENY" / "PERMIT" / "DROP"

`context` is the shared dictionary built by main.py and warmUp.py.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

# Folder of your submission. Trained models are saved here, next to the template files.
# Load this task's model by its uploaded name, e.g. MODELS_DIR / "abc123_generateIOCReport.onnx".
# If your approach uses trained models, see the rules in warmUp.py.
SUBMISSION_DIR = Path(__file__).parent
MODELS_DIR = SUBMISSION_DIR


def generate_report(results: pd.DataFrame, output_dir: Path, context: dict) -> list[Path]:
    """Write the IOC report into output_dir and return the paths of the files written."""

    # TODO: write the report in the required format and return its file path(s).
    written: list[Path] = []

    return written
