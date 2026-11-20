"""
benchmark.py - Local detection benchmark

Runs your whole pipeline through main.py, exactly as grading does (a fresh `python main.py ...` for every test set), on up to three labelled test sets that you build yourself, and prints your detection accuracy on each one: 
    the share of packets whose final action (DENY, PERMIT or DROP) equals the `verdict` column. 
This is computed the same way grading computes detection. 
It also shows, for each true verdict, which final actions your pipeline gave, so you can see where it goes wrong.

    python benchmark.py --normal normal.csv --attack attack.csv --realistic realistic.csv --policies policy.yaml --output benchmarkRun

You may give one, two or all three sets. When you give all three, it also prints an estimate of your detection score out of 60 (normal 15, attack 15, realistic 30). 
Each set's outputs (predictions.csv, run_metadata.json, the IOC report and the pipeline's own log) are kept in <output>/normal, <output>/attack and <output>/realistic.

This is a tool for your own iteration, not a grade, and a local result does not guarantee the same result on the portal.
Only detection is estimated here: the IOC report and efficiency are graded only on the portal.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import pandas as pd

SUBMISSION_DIR = Path(__file__).resolve().parent
DETECTION_POINTS = {"normal": 15, "attack": 15, "realistic": 30}
ACTIONS = ("DENY", "PERMIT", "DROP")
LOG_LINES_SHOWN = 15


def read_truth(csv_path: Path) -> tuple[pd.Series, pd.Series | None]:
    """The verdict of every packet, in file order (the true final action), and the Label column if there is one."""
    labelled = pd.read_csv(csv_path, low_memory=False, keep_default_na=False)
    labelled.columns = labelled.columns.str.strip()
    if "verdict" not in labelled.columns:
        raise ValueError(f"{csv_path} has no verdict column, so detection cannot be measured. Build your test sets in the dataset format.")
    verdicts = labelled["verdict"].astype(str).str.strip().str.upper()
    unknown = sorted(set(verdicts) - set(ACTIONS))
    if unknown:
        raise ValueError(f"{csv_path}: every verdict must be DENY, PERMIT or DROP; found {unknown[:5]}")
    label_column = "Label" if "Label" in labelled.columns else "label" if "label" in labelled.columns else None
    labels = labelled[label_column].astype(str).str.strip() if label_column else None
    return verdicts.reset_index(drop=True), labels


def run_pipeline(csv_path: Path, policies: Path, output_dir: Path) -> tuple[bool, str]:
    """Run main.py in a fresh process, as grading does; return (succeeded, log text)."""
    output_dir.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, "main.py", "--input", str(csv_path), "--policies", str(policies), "--output", str(output_dir)]
    finished = subprocess.run(command, cwd=SUBMISSION_DIR, capture_output=True, text=True)
    log = finished.stdout + finished.stderr
    (output_dir / "pipeline.log").write_text(log, encoding="utf-8")
    return finished.returncode == 0, log


def print_breakdown(truth: pd.Series, final: pd.Series) -> None:
    """For each true verdict, how many packets got each final action."""
    print(f"    {'true verdict':<14}" + "".join(f"{action:>10}" for action in ACTIONS) + f"{'correct':>10}")
    for true_action in ACTIONS:
        rows = final[truth == true_action]
        if rows.empty:
            continue
        counts = "".join(f"{int((rows == action).sum()):>10}" for action in ACTIONS)
        print(f"    {true_action:<14}{counts}{(rows == true_action).mean():>10.4f}")


def check_set_contents(name: str, labels: pd.Series | None) -> None:
    """Warn when a normal set holds attacks or an attack set holds normal traffic."""
    if labels is None:
        return
    if name == "normal" and (labels != "0").any():
        print(f"    note: this normal set has {int((labels != '0').sum())} attack packets (Label 1); the graded normal dataset has none.")
    if name == "attack" and (labels != "1").any():
        print(f"    note: this attack set has {int((labels != '1').sum())} normal packets (Label 0); the graded attack dataset has none.")


def benchmark_set(name: str, csv_path: Path, policies: Path, output_root: Path) -> float:
    """Run one test set and print its detection accuracy; a failed run counts as 0, as in grading."""
    print(f"\n{name} set: {csv_path}")
    truth, labels = read_truth(csv_path)
    check_set_contents(name, labels)
    output_dir = output_root / name
    succeeded, log = run_pipeline(csv_path.resolve(), policies.resolve(), output_dir.resolve())
    if not succeeded:
        print(f"    Your pipeline exited with an error on this set, so its detection counts as 0. Last lines of {output_dir / 'pipeline.log'}:")
        for line in log.strip().splitlines()[-LOG_LINES_SHOWN:]:
            print(f"      {line}")
        return 0.0
    predictions = pd.read_csv(output_dir / "predictions.csv", keep_default_na=False).sort_values("packet_id")
    final = predictions["final_action"].astype(str).str.strip().reset_index(drop=True)
    if len(final) != len(truth):
        print(f"    predictions.csv has {len(final)} rows but the set has {len(truth)} packets, so its detection counts as 0.")
        return 0.0
    accuracy = float((final == truth).mean())
    print(f"    {len(truth)} packets, detection accuracy {accuracy:.4f} ({int((final == truth).sum())} final actions correct)")
    print_breakdown(truth, final)
    report_extra_files(output_dir, output_root)
    return accuracy


def report_extra_files(output_dir: Path, output_root: Path) -> None:
    """Point out files that would cost points in a portal submission (this benchmark's own outputs left aside)."""
    try:
        metadata = json.loads((output_dir / "run_metadata.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    output_prefix = output_root.resolve()
    extras = [name for name in metadata.get("extra_files", []) if not (SUBMISSION_DIR / name).resolve().is_relative_to(output_prefix)]
    if extras:
        shown = ", ".join(extras[:5]) + (f" and {len(extras) - 5} more" if len(extras) > 5 else "")
        print(f"    note: {len(extras)} file(s) here are not part of a production-ready submission ({shown}); uploading any to the portal deducts 5 points.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Local detection benchmark: run your pipeline on your own labelled test sets")
    parser.add_argument("--normal", type=Path, help="labelled CSV with normal traffic only")
    parser.add_argument("--attack", type=Path, help="labelled CSV with attack traffic only")
    parser.add_argument("--realistic", type=Path, help="labelled CSV mixing normal and attack traffic")
    parser.add_argument("--policies", required=True, type=Path, help="policy document (policy.yaml)")
    parser.add_argument("--output", required=True, type=Path, help="folder for each set's outputs")
    args = parser.parse_args()
    sets = {name: getattr(args, name) for name in DETECTION_POINTS if getattr(args, name) is not None}
    if not sets:
        parser.error("give at least one of --normal, --attack and --realistic")
    for path in [*sets.values(), args.policies]:
        if not path.is_file():
            parser.error(f"file not found: {path}")

    accuracies = {}
    for name, csv_path in sets.items():
        try:
            accuracies[name] = benchmark_set(name, csv_path, args.policies, args.output)
        except ValueError as error:
            print(f"    {error}")
            return 1

    print("\nDetection accuracy")
    for name, accuracy in accuracies.items():
        print(f"    {name:<10} {accuracy:.4f}   (worth {DETECTION_POINTS[name]} points in grading)")
    if len(accuracies) == len(DETECTION_POINTS):
        estimate = sum(DETECTION_POINTS[name] * accuracy for name, accuracy in accuracies.items())
        print(f"    Estimated detection score: {estimate:.2f} / 60")
    else:
        print("    Give all three sets (--normal, --attack, --realistic) for an estimate of your detection score out of 60.")
    print("\nThis is for your own iteration, not a grade. The IOC report and efficiency are graded only on the portal.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
