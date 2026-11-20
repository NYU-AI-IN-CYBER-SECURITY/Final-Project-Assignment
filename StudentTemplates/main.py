"""
main.py - Pipeline orchestrator (entry point; do not rename this file)

The grader runs your pipeline with exactly this command:

    python main.py --input <test.csv> --policies <policy.yaml> --output <output_dir>

What happens, in order:
  1. The CSV is loaded. Ground-truth columns (`label`/`Label`, `attack_cat`, `verdict`) are removed if present, and every row (packet) gets a `packet_id` (0..N-1, in file order), replacing any `packet_id` column already in the file.
  2. The policy document is loaded with checkPolicy.load_policies().
  3. warmUp.warm_up() runs (optional; switch it off with RUN_WARM_UP).
  4. The three analysis stages run in the order you set in PIPELINE_ORDER:
        "policy"     -> checkPolicy.check_policy()
        "binary"     -> binaryClassification.classify_binary()
        "multiclass" -> multiClassClassification.classify_multiclass()
     Every stage receives (packets, context). context["stage_results"] holds the validated outputs of the stages that have already run, keyed by stage name, so a later stage can use an earlier stage's results if you want it to.
  5. The results are merged and every packet gets a final action:
        DENY             if the packet violates any policy (DENY always wins)
        PERMIT or DROP   otherwise, decided by resolve_conflict() below
  6. predictions.csv and run_metadata.json are written to <output_dir>.
  7. generateIOCReport.generate_report() writes the IOC report.
  8. The trained model files in this folder (if any) are listed in run_metadata.json, and so are, as extra_files, any other files that are not part of a production-ready submission (with a warning).

What you MAY change: everything inside the STUDENT CONFIG block.
What you must NOT change: the command-line arguments, the output file names, and the column names / values enforced by validate_stage_output(). Grading depends on them.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

import binaryClassification
import checkPolicy
import generateIOCReport
import multiClassClassification
import warmUp

# ============================== STUDENT CONFIG ==============================

# Order of the three analysis tasks. Required: set it before you run.
# Use each of "multiclass", "policy" and "binary" exactly once, in any order.
# For example, PIPELINE_ORDER = ["multiclass", "binary", "policy"] would start with multiclass first.
PIPELINE_ORDER = []

# Call warmUp.warm_up() once before the stages run (optional one-off setup).
RUN_WARM_UP = True

# If True, any classifier that runs after checkPolicy only receives the packets that were not denied.
# Denied packets never reach that classifier.
SKIP_CLASSIFICATION_FOR_DENIED = False

# Explain your conflict rule (written to run_metadata.json for the grader).
CONFLICT_RULE_DESCRIPTION = (
    "TODO: explain how you resolve disagreements between the binary and multi-class classifiers, and why."
)


def resolve_conflict(binary_action: str, multiclass_action: str, packet: dict) -> str:
    """Return "PERMIT" or "DROP" for a packet that was NOT denied by policy.

    binary_action / multiclass_action are "PERMIT" or "DROP" ("" if that classifier skipped the packet). `packet` is a dict holding the full merged row (input columns, predictions, confidences), e.g. packet["binary_confidence"].

    TODO: replace the placeholder below with your own rule and justify it in
    CONFLICT_RULE_DESCRIPTION.
    """
    if binary_action == multiclass_action:
        return binary_action
    # Placeholder only (not a recommendation): trust the binary classifier.
    return binary_action or multiclass_action


# ============================ END STUDENT CONFIG ============================


ID = "packet_id"
GROUND_TRUTH_COLUMNS = ("label", "Label", "attack_cat", "verdict")
PROBABILITY = "probability"  # marker: numeric column, values in [0, 1] or NaN
# Model files are recognized by their extension (see warmUp.py); a .json file only when it is named like a model.
MODEL_EXTENSIONS = (".onnx", ".joblib", ".pkl", ".ubj", ".gguf")
MODEL_TASKS = ("multiClassClassification", "checkPolicy", "binaryClassification", "generateIOCReport")
MODEL_NAME_PATTERN = re.compile(rf"^[A-Za-z]{{2,}}[0-9]+_({'|'.join(MODEL_TASKS)})_[A-Za-z0-9-]+\.[A-Za-z0-9]+$")
# Besides .py files and model files, a production-ready submission holds only these.
SUBMISSION_NAMES = ("requirements.txt", "policy.yaml", "token.txt")
SKIPPED_FOLDERS = ("__pycache__", ".git", "venv", ".venv")

# Columns each stage must return (besides packet_id) and their allowed values.
STAGE_SPECS = {
    "policy": {
        "func": checkPolicy.check_policy,
        "columns": {
            "policy_decision": ("DENY", "ALLOW"),
            "violated_policy": None,
            "policy_reason": None,
        },
    },
    "binary": {
        "func": binaryClassification.classify_binary,
        "columns": {
            "binary_pred": (0, 1),
            "binary_confidence": PROBABILITY,
        },
    },
    "multiclass": {
        "func": multiClassClassification.classify_multiclass,
        "columns": {
            "attack_cat_pred": multiClassClassification.ATTACK_CATEGORIES,
            "multiclass_confidence": PROBABILITY,
        },
    },
}

PREDICTION_COLUMNS = [ID, "policy_decision", "violated_policy", "policy_reason", "binary_pred", "binary_confidence", "binary_action", "attack_cat_pred", "multiclass_confidence", "multiclass_action", "final_action"]


def log(message: str) -> None:
    print(f"[pipeline] {message}", file=sys.stderr, flush=True)


def check_config() -> None:
    if not PIPELINE_ORDER:
        raise SystemExit(
            'PIPELINE_ORDER is empty. Set it in the STUDENT CONFIG block of main.py, '
            'using each of "multiclass", "policy" and "binary" exactly once.'
        )
    if sorted(PIPELINE_ORDER) != sorted(STAGE_SPECS):
        raise SystemExit(
            f'PIPELINE_ORDER must use each of "multiclass", "policy" and "binary" exactly once, got {PIPELINE_ORDER}'
        )


def is_model_file(path: Path) -> bool:
    """A model file by extension: .onnx, .joblib, .pkl, .ubj, .gguf, or .json when named like a model."""
    suffix = path.suffix.lower()
    return suffix in MODEL_EXTENSIONS or (suffix == ".json" and bool(MODEL_NAME_PATTERN.match(path.name)))


def submission_files(output_dir: Path) -> tuple[list[Path], list[Path]]:
    """(model files, extra files) in the submission folder, leaving out this run's outputs.

    Extra files are everything that is not a .py file, requirements.txt, token.txt or a model file, and every file inside
    a folder: they are not part of a production-ready submission.
    """
    submission_dir = Path(__file__).resolve().parent
    output_dir = output_dir.resolve()
    models, extras = [], []
    for p in sorted(submission_dir.rglob("*")):
        folders = p.relative_to(submission_dir).parts[:-1]
        if not p.is_file() or any(folder in SKIPPED_FOLDERS for folder in folders) or p.resolve().is_relative_to(output_dir):
            continue
        if folders:
            extras.append(p)
        elif is_model_file(p):
            models.append(p)
        elif p.suffix.lower() != ".py" and p.name not in SUBMISSION_NAMES:
            extras.append(p)
    return models, extras


def list_model_files(output_dir: Path) -> list[dict]:
    """Model files in the submission folder (see warmUp.py), for the grader."""
    submission_dir = Path(__file__).resolve().parent
    return [
        {"file": p.relative_to(submission_dir).as_posix(), "format": p.suffix.lower().lstrip("."), "size_mb": round(p.stat().st_size / 1e6, 2)}
        for p in submission_files(output_dir)[0]
    ]


def list_extra_files(output_dir: Path) -> list[str]:
    """Files that are not part of a production-ready submission; uploading any of them to the portal deducts 5 points."""
    submission_dir = Path(__file__).resolve().parent
    return [p.relative_to(submission_dir).as_posix() for p in submission_files(output_dir)[1]]


def load_packets(path: Path) -> pd.DataFrame:
    packets = pd.read_csv(path, low_memory=False)
    packets.columns = packets.columns.str.strip()
    present = [c for c in GROUND_TRUTH_COLUMNS if c in packets.columns]
    if present:
        log(f"Removing ground-truth columns from input: {present}")
        packets = packets.drop(columns=present)
    # The labelled CSVs carry their own 1-based packet_id; replace it with the 0-based row number.
    packets = packets.drop(columns=[ID], errors="ignore")
    packets.insert(0, ID, np.arange(len(packets)))
    return packets


def validate_stage_output(stage: str, out, expected_ids: pd.Series) -> pd.DataFrame:
    spec = STAGE_SPECS[stage]
    where = f"{stage} stage ({spec['func'].__module__}.{spec['func'].__name__})"

    if not isinstance(out, pd.DataFrame):
        raise TypeError(f"{where} must return a pandas DataFrame, got {type(out).__name__}")

    missing = [c for c in [ID, *spec["columns"]] if c not in out.columns]
    if missing:
        raise ValueError(f"{where} output is missing columns: {missing}")

    out = out.copy()
    # Accept ids as numbers or numeric strings (e.g. parsed from text), stored as int.
    ids = pd.to_numeric(out[ID], errors="coerce")
    if ids.isna().any() or (ids % 1 != 0).any():
        bad = out.loc[ids.isna() | (ids % 1 != 0), ID].astype(str).unique()[:5]
        raise ValueError(f"{where}: packet_id values must be integers, got e.g. {list(bad)}")
    out[ID] = ids.astype("int64")

    if out[ID].duplicated().any():
        dupes = out.loc[out[ID].duplicated(), ID].unique()[:5]
        raise ValueError(f"{where} returned duplicate packet_ids, e.g. {list(dupes)}")
    expected, got = set(expected_ids), set(out[ID])
    if got != expected:
        missing, extra = sorted(expected - got)[:5], sorted(got - expected)[:5]
        raise ValueError(
            f"{where} must return exactly one row per input packet "
            f"({len(expected)} packets, got {len(got)}). "
            f"Missing packet_ids e.g. {missing}; unexpected packet_ids e.g. {extra}"
        )

    for col, allowed in spec["columns"].items():
        if allowed is None:
            continue
        if allowed == PROBABILITY:
            try:
                out[col] = pd.to_numeric(out[col]).astype(float)  # None -> NaN, "0.9" -> 0.9
            except (TypeError, ValueError):
                raise ValueError(
                    f"{where}: column {col!r} must be numbers in [0, 1], or NaN/None if unknown"
                ) from None
            tolerance = 1e-4  # float32 rounding, e.g. 1.0000001 from an ONNX model
            if ((out[col] < -tolerance) | (out[col] > 1 + tolerance)).any():
                raise ValueError(f"{where}: column {col!r} must be within [0, 1] or NaN")
            out[col] = out[col].clip(0, 1)
        else:
            bad = ~out[col].isin(allowed)
            if bad.any():
                examples = sorted(map(str, out.loc[bad, col].unique()))[:5]
                raise ValueError(
                    f"{where}: column {col!r} has invalid values {examples}; "
                    f"allowed: {list(allowed)}"
                )
            if col == "binary_pred":
                out[col] = out[col].astype("int64")  # True/False or 1.0/0.0 -> 1/0

    return out[[ID, *spec["columns"]]]


def run_stage(stage: str, packets: pd.DataFrame, context: dict, results: dict):
    subset = packets
    if SKIP_CLASSIFICATION_FOR_DENIED and stage != "policy" and "policy" in results:
        policy = results["policy"]
        denied = policy.loc[policy["policy_decision"] == "DENY", ID]
        subset = packets[~packets[ID].isin(denied)]
        log(f"{stage}: skipping {len(denied)} denied packets")

    spec = STAGE_SPECS[stage]
    start = time.perf_counter()
    if len(subset) == 0:
        out = pd.DataFrame({c: pd.Series(dtype=float) for c in [ID, *spec["columns"]]})
    else:
        # A copy, so a stage cannot change the packets other stages see.
        out = spec["func"](subset.copy(), context)
    elapsed = time.perf_counter() - start

    out = validate_stage_output(stage, out, subset[ID])
    log(f"{stage}: {len(subset)} packets in {elapsed:.2f}s")
    return out, elapsed


def merge_results(packets: pd.DataFrame, results: dict) -> pd.DataFrame:
    merged = packets.copy()
    for stage in STAGE_SPECS:
        merged = merged.merge(results[stage], on=ID, how="left")

    merged["binary_pred"] = merged["binary_pred"].astype("Int64")
    merged["binary_action"] = (merged["binary_pred"].map({0: "PERMIT", 1: "DROP"}).astype(object).fillna(""))
    merged["multiclass_action"] = np.where(merged["attack_cat_pred"].isna(), "", np.where(merged["attack_cat_pred"] == "Normal", "PERMIT", "DROP"))
    for col in ("violated_policy", "policy_reason"):
        merged[col] = merged[col].fillna("")

    merged["final_action"] = [decide_final(row) for row in merged.to_dict("records")]
    return merged


def decide_final(row: dict) -> str:
    if row["policy_decision"] == "DENY":
        return "DENY"
    action = resolve_conflict(row["binary_action"], row["multiclass_action"], row)
    if action not in ("PERMIT", "DROP"):
        raise ValueError(
            f"resolve_conflict() returned {action!r} for packet {row[ID]}; "
            "it must return 'PERMIT' or 'DROP'"
        )
    return action


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Packet analysis pipeline")
    parser.add_argument("--input", required=True, type=Path, help="CSV of packets to analyse")
    parser.add_argument("--policies", required=True, type=Path, help="policy document")
    parser.add_argument("--output", required=True, type=Path, help="directory for outputs")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    check_config()
    if not args.input.is_file():
        log(f"Input CSV not found: {args.input}")
        return 1
    if not args.policies.is_file():
        log(f"Policy file not found: {args.policies}")
        return 1
    args.output.mkdir(parents=True, exist_ok=True)

    total_start = time.perf_counter()
    packets = load_packets(args.input)
    log(f"Loaded {len(packets)} packets from {args.input}")

    context = {
        "output_dir": args.output,
        "policies": checkPolicy.load_policies(args.policies),
    }

    timings = {}
    if RUN_WARM_UP:
        start = time.perf_counter()
        returned = warmUp.warm_up(context)
        if isinstance(returned, dict):
            context = returned
        timings["warm_up"] = time.perf_counter() - start
        log(f"warm-up done in {timings['warm_up']:.2f}s")

    results = {}
    for stage in PIPELINE_ORDER:
        # Copies, so a stage can read earlier results but not alter what gets merged.
        context["stage_results"] = {name: out.copy() for name, out in results.items()}
        results[stage], timings[stage] = run_stage(stage, packets, context, results)

    merged = merge_results(packets, results)
    merged[PREDICTION_COLUMNS].to_csv(args.output / "predictions.csv", index=False)

    start = time.perf_counter()
    report_files = generateIOCReport.generate_report(merged, args.output, context) or []
    if not report_files:
        log("WARNING: generateIOCReport.generate_report() did not return any report files")
    timings["report"] = time.perf_counter() - start
    timings["total"] = time.perf_counter() - total_start

    metadata = {
        "input": str(args.input),
        "policies": str(args.policies),
        "packets": int(len(packets)),
        "pipeline_order": PIPELINE_ORDER,
        "warm_up": RUN_WARM_UP,
        "skip_classification_for_denied": SKIP_CLASSIFICATION_FOR_DENIED,
        "conflict_rule": CONFLICT_RULE_DESCRIPTION,
        "final_action_counts": {k: int(v) for k, v in merged["final_action"].value_counts().items()},
        "timings_seconds": {k: round(v, 3) for k, v in timings.items()},
        "report_files": [str(p) for p in report_files],
        "model_files": list_model_files(args.output),
        "extra_files": list_extra_files(args.output),
    }
    (args.output / "run_metadata.json").write_text(json.dumps(metadata, indent=2))
    if metadata["extra_files"]:
        log(f"WARNING: {len(metadata['extra_files'])} file(s) in this folder are not part of a production-ready submission "
            "(listed as extra_files in run_metadata.json). Uploading any of them to the portal deducts 5 points.")

    log(f"Done in {timings['total']:.2f}s. Outputs in {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
