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

Run this module on its own to check that your report can be read by the grader. 
It runs your whole pipeline through main.py, exactly as grading does, then checks every entry of the report against the required format (the same rules as grading) and checks that the report agrees with your own predictions.csv.
This is not a grade on the quality of your report: the IOC report quality is graded only on the portal.
    
    python generateIOCReport.py --input labelled.csv --policies policy.yaml --output reportCheck
"""

from __future__ import annotations

import argparse
from pathlib import Path

import pandas as pd

# Folder of your submission. Trained models are saved here, next to the template files.
# Load this task's model files by their uploaded names, e.g. MODELS_DIR / "abc123_generateIOCReport_llm.gguf".
# If your approach uses trained models, see the rules in warmUp.py.
SUBMISSION_DIR = Path(__file__).parent
MODELS_DIR = SUBMISSION_DIR


def generate_report(results: pd.DataFrame, output_dir: Path, context: dict) -> list[Path]:
    """Write the IOC report into output_dir and return the paths of the files written."""

    # TODO: write the report in the required format and return its file path(s).
    written: list[Path] = []

    return written


if __name__ == "__main__":
    import ipaddress
    import json
    import re
    import sys

    import main
    import multiClassClassification

    parser = argparse.ArgumentParser(description="Run your pipeline and check that the IOC report it writes is well formed")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--policies", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    # The format rules grading applies to every entry.
    ENTRY_KEYS = {"verdict", "stix"}
    TRAFFIC_KEYS = {"type", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp", "packet_index"}
    INDICATOR_KEYS = {"type", "category", "policy_rule", "severity", "summary"}
    TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
    POLICY_RULE_PATTERN = re.compile(r"^POL-\d+(;POL-\d+)*$")
    CATEGORIES = set(multiClassClassification.ATTACK_CATEGORIES) | {"Backdoors"}
    NO_PORT = "-"
    DROP_SEVERITY = {"Exploits": "high", "Backdoor": "high", "Shellcode": "high", "Worms": "high",
                     "Fuzzers": "medium", "Generic": "medium", "Analysis": "low", "Reconnaissance": "low", "Normal": "low"}
    SHOWN_PROBLEMS = 5

    def as_port(value):
        """A port column value as an int (decimal, hexadecimal such as 0x000b, or 80.0), or the text itself (e.g. "-")."""
        text = str(value).strip()
        for convert in (lambda t: int(t, 0), lambda t: int(float(t))):
            try:
                return convert(text)
            except ValueError:
                continue
        return text

    def packet_key(timestamp, src_ip, src_port, dst_ip, dst_port, protocol):
        values = (timestamp, src_ip, as_port(src_port), dst_ip, as_port(dst_port), protocol)
        return tuple(str(value).strip().lower() for value in values)

    def is_ip(value):
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def is_port(value):
        return type(value) is int and 0 <= value <= 65535

    def entry_problem(entry, no_port_keys):
        """The first format problem in one entry, or None if it is valid.

        no_port_keys holds the packets whose sport or dsport column is "-": only there may a port be the string "-".
        """
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
            return "entry must have exactly the keys verdict and stix"
        if entry["verdict"] not in ("drop", "deny"):
            return f"verdict must be 'drop' or 'deny', got {entry['verdict']!r}"
        stix = entry["stix"]
        if not isinstance(stix, dict) or set(stix) != {"type", "objects"} or stix["type"] != "bundle":
            return "stix must be a bundle with the keys type and objects"
        objects = stix["objects"]
        if not isinstance(objects, list) or len(objects) != 2:
            return "stix.objects must hold one network-traffic and one indicator object"
        traffic, indicator = objects
        if not isinstance(traffic, dict) or set(traffic) != TRAFFIC_KEYS or traffic["type"] != "network-traffic":
            return f"first object must be network-traffic with the keys {sorted(TRAFFIC_KEYS)}"
        if not is_ip(traffic["src_ip"]) or not is_ip(traffic["dst_ip"]):
            return "src_ip and dst_ip must be IP addresses"
        for name in ("src_port", "dst_port"):
            if traffic[name] == NO_PORT:
                key = packet_key(traffic["timestamp"], traffic["src_ip"], traffic["src_port"], traffic["dst_ip"], traffic["dst_port"], traffic["protocol"])
                if key not in no_port_keys:
                    return f'{name} may be "-" only for a packet whose {"sport" if name == "src_port" else "dsport"} column is -'
            elif not is_port(traffic[name]):
                return f'{name} must be an integer from 0 to 65535, or "-" when the column is -'
        if not isinstance(traffic["protocol"], str) or not traffic["protocol"]:
            return "protocol must be a non-empty string"
        if not isinstance(traffic["timestamp"], str) or not TIMESTAMP_PATTERN.match(traffic["timestamp"]):
            return "timestamp must look like 2026-10-27T00:11:34.227Z"
        if type(traffic["packet_index"]) is not int or traffic["packet_index"] < 0:
            return "packet_index must be a non-negative integer"
        if not isinstance(indicator, dict) or set(indicator) != INDICATOR_KEYS or indicator["type"] != "indicator":
            return f"second object must be indicator with the keys {sorted(INDICATOR_KEYS)}"
        category, rule = indicator["category"], indicator["policy_rule"]
        if entry["verdict"] == "deny" and category is None:
            pass
        elif category not in CATEGORIES:
            if entry["verdict"] == "deny":
                return f"category of a deny entry must be null, Normal or an attack category, got {category!r}"
            return f"category of a drop entry must be Normal or an attack category, got {category!r}"
        if rule is not None and not (isinstance(rule, str) and POLICY_RULE_PATTERN.match(rule)):
            return f"policy_rule must be null or look like POL-1, got {rule!r}"
        if indicator["severity"] not in ("low", "medium", "high"):
            return f"severity must be low, medium or high, got {indicator['severity']!r}"
        if not isinstance(indicator["summary"], str) or not indicator["summary"].strip():
            return "summary must be a non-empty string"
        if entry["verdict"] == "deny" and rule is None:
            return "a deny entry must name its policy_rule"
        if entry["verdict"] == "drop" and rule is not None:
            return "a drop entry must have a null policy_rule"
        return None

    def same_category(name):
        return "Backdoor" if name == "Backdoors" else name

    def expected_severity(verdict, category):
        return "high" if verdict == "deny" else DROP_SEVERITY.get(category, "low")

    def rule_set(rule):
        return frozenset(str(rule).split(";")) if rule else frozenset()

    def show(title, problems, total):
        """One line per check: how many entries pass, and the first few that do not."""
        print(f"{title:<28} {total - len(problems)} of {total} correct")
        for problem in problems[:SHOWN_PROBLEMS]:
            print(f"    {problem}")
        if len(problems) > SHOWN_PROBLEMS:
            print(f"    ... and {len(problems) - SHOWN_PROBLEMS} more")

    # 1. Your whole pipeline, run exactly as grading runs it.
    exit_code = main.main(["--input", str(args.input), "--policies", str(args.policies), "--output", str(args.output)])
    if exit_code:
        sys.exit(exit_code)
    metadata = json.loads((args.output / "run_metadata.json").read_text(encoding="utf-8"))
    # Like grading: the first .json path generate_report() returned, else any other .json file in the output folder.
    candidates = [Path(path) for path in metadata.get("report_files", [])] + sorted(args.output.glob("*.json"))
    report_paths = [path for path in candidates if path.suffix.lower() == ".json" and path.name != "run_metadata.json" and path.is_file()]
    if not report_paths:
        sys.exit("\nNo IOC report: generate_report() must write a .json file to output_dir and return its path. An unreadable report scores zero.")
    report_path = report_paths[0]
    print(f"\nChecking {report_path}")
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        sys.exit(f"The report is not valid JSON ({error}). An IOC report that cannot be parsed scores zero.")
    if not isinstance(report, list) or not report:
        sys.exit("The report must be a non-empty JSON array of entries.")

    packets = main.load_packets(args.input)
    no_port_keys = {
        packet_key(row["timestamp"], row["srcip"], row["sport"], row["dstip"], row["dsport"], row["proto"])
        for row in packets.to_dict("records")
        if str(row["sport"]).strip() == NO_PORT or str(row["dsport"]).strip() == NO_PORT
    }

    # 2. Format, with the same rules as grading.
    print("\nFormat (the same rules as grading):")
    problems = [f"entry {position}: {problem}" for position, entry in enumerate(report) if (problem := entry_problem(entry, no_port_keys))]
    show("valid entries", problems, len(report))
    valid = [entry for entry in report if entry_problem(entry, no_port_keys) is None]

    # 3. Against your own predictions.csv: one entry per DROP or DENY packet, with fields that follow from your results.
    predictions = pd.read_csv(args.output / "predictions.csv", keep_default_na=False)
    flagged = predictions[predictions["final_action"].isin(["DROP", "DENY"])]
    by_index = {}
    for entry in valid:
        by_index.setdefault(entry["stix"]["objects"][0]["packet_index"], entry)
    print(f"\nAgainst your own predictions.csv ({len(flagged)} DROP or DENY packets):")
    listed = set(by_index)
    expected_ids = set(flagged["packet_id"].astype(int))
    missing, extra = sorted(expected_ids - listed), sorted(listed - expected_ids)
    listing = [f"packet_id {pid}: no valid entry" for pid in missing] + [f"packet_index {pid}: listed, but this packet is PERMIT" for pid in extra]
    print(f"{'entries listed':<28} {len(expected_ids & listed)} of {len(expected_ids)} DROP/DENY packets ({len(extra)} extra)")
    for problem in listing[:SHOWN_PROBLEMS]:
        print(f"    {problem}")
    checks = {"verdict": [], "category": [], "policy_rule": [], "severity": [], "packet fields": []}
    matched = 0
    for row in flagged.to_dict("records"):
        pid = int(row["packet_id"])
        entry = by_index.get(pid)
        if entry is None:
            continue
        matched += 1
        traffic, indicator = entry["stix"]["objects"]
        verdict = row["final_action"].lower()
        if entry["verdict"] != verdict:
            checks["verdict"].append(f"packet_id {pid}: verdict {entry['verdict']!r}, but final_action is {row['final_action']}")
        predicted = same_category(row["attack_cat_pred"]) if row["attack_cat_pred"] != "" else None
        category = indicator["category"]
        # The category is the predicted attack category. A deny entry may leave it null instead (policy short-circuit).
        if verdict == "deny" and category is None:
            pass
        elif predicted is None:
            checks["category"].append(f"packet_id {pid}: category {category!r}, but the packet was not classified")
        elif same_category(category) != predicted:
            checks["category"].append(f"packet_id {pid}: category {category!r}, but attack_cat_pred is {predicted!r}")
        wanted_rule = rule_set(row["violated_policy"]) if verdict == "deny" else frozenset()
        if rule_set(indicator["policy_rule"]) != wanted_rule:
            checks["policy_rule"].append(f"packet_id {pid}: policy_rule {indicator['policy_rule']!r}, but violated_policy is {row['violated_policy']!r}")
        if indicator["severity"] != expected_severity(entry["verdict"], same_category(category)):
            checks["severity"].append(f"packet_id {pid}: severity {indicator['severity']!r} does not follow the README table for a {entry['verdict']} {category} entry")
        packet = packets.iloc[pid]
        fields = {"src_ip": str(packet["srcip"]), "dst_ip": str(packet["dstip"]), "protocol": str(packet["proto"]), "timestamp": str(packet["timestamp"])}
        wrong = [name for name, value in fields.items() if str(traffic[name]) != value.strip()]
        wrong += [name for name, column in (("src_port", "sport"), ("dst_port", "dsport")) if traffic[name] != as_port(packet[column])]
        if wrong:
            checks["packet fields"].append(f"packet_id {pid}: {', '.join(wrong)} do not match the input row")
    for title, found in checks.items():
        show(title, found, matched)
    print("\nThis check is not a grade on the quality of your IOC report: it shows only that the report is well formed and "
          "consistent with your own predictions. The IOC report is graded only on the portal.")
