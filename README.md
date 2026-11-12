# Final Project: Packet Analysis Pipeline

## Overview

Build a pipeline that takes a CSV file of network packets (one row per packet) and performs four tasks:

- **Multi-class classification.** Predict, for every packet, its attack category. `Normal` means **PERMIT**; any other category means **DROP**.
- **Policy checking.** Decide, for every packet, whether it violates any of the given policies. A packet that violates a policy is **DENY**.
- **Binary classification.** Predict, for every packet, whether it is normal (`0`) or an attack (`1`). Normal means **PERMIT**; attack means **DROP**.
- **IOC report.** Generate a report from the results of multi-class classification, policy checking and binary classification.

Every packet receives one final action:

- **DENY** if it violates any policy. DENY always takes precedence over PERMIT and DROP.
- Otherwise **PERMIT** or **DROP**, decided by your own rule for combining the two classification results.

Provided separately:

- the labelled dataset,
- the policy document (`policy.yaml`).

## The dataset

The packets come from the UNSW-NB15 dataset. We use **all** of its formats and possible values exactly as they are provided in UNSW-NB15, without cleaning or converting them for you. Your pipeline must handle every format and value that can appear in any column, including the port, protocol and category columns.

The labelled dataset has three ground-truth columns, which are removed before your pipeline runs:

| Column | Meaning |
|---|---|
| `Label` | `0` if the packet is normal, `1` if it is an attack. This is what binary classification predicts. |
| `attack_cat` | The attack category of the packet. This is what multi-class classification predicts. |
| `verdict` | The expected final action for the packet: `DENY`, `PERMIT` or `DROP`. |

**DoS has been removed as a category for the final project.** We discussed DoS in the earlier assignments and recognize the limitations of that category in this dataset, so it is not one of the categories you predict.

## How your work is measured

We measure the final result your pipeline produces. Two things count, and you must balance them against each other:

- **Accuracy:** how correct the full outcome of your pipeline is, not only one task. Accuracy is weighted higher than efficiency. Output that cannot be read scores zero: for example, an incorrectly formatted JSON file that cannot be parsed scores zero.
- **Efficiency:** how fast your pipeline processes packets, and how few resources it uses to do so. We measure the total memory used and the CPU cycles, including normalized wall-clock time: the number of seconds your pipeline takes to do its work, measured on our own fixed hardware so that every submission is compared on the same machine.

Everything your pipeline does counts toward efficiency, including `warm_up()`, since it is part of your system.

Deciding where the balance between accuracy and efficiency lies is part of the project. `run_metadata.json` records the time taken by each part of your pipeline, which you can use to measure your own efficiency while you work.

## Your design is your choice

You decide how your pipeline works. The sequence of the tasks, the flow of data between them, the approach used for each task, and the way the results are combined are all for you to work out and justify. For example, a task that runs later may use the results of tasks that ran earlier (see [Shared context](#shared-context)). We measure the final result, not the route you took to it, as long as you stay within the rules below.

## What you need to do

- Implement each task in its module of the starter template, meeting the [interface requirements](#interface-requirements).
- In the `STUDENT CONFIG` block of `main.py`, set the order of the analysis tasks and the other settings, implement your rule for combining the two classification results, and describe that rule.
- Generate the IOC report in the [required format](#ioc-report-format).
- If your pipeline uses trained models, follow the rules in [Trained models](#trained-models).
- List every package your pipeline needs in `requirements.txt`, with a pinned version (see [Python version and packages](#python-version-and-packages)).
- Check that your pipeline runs from a fresh Python environment with the command in [How your pipeline is run](#how-your-pipeline-is-run).
- Submit your completed template folder as described in [What to submit](#what-to-submit).

## Starter template

| File | Purpose | Your work |
|---|---|---|
| `main.py` | Orchestrator: runs the pipeline and writes the outputs | Edit the `STUDENT CONFIG` block only |
| `multiClassClassification.py` | Multi-class classification | Implement `classify_multiclass()` |
| `checkPolicy.py` | Policy checking | Implement `check_policy()`; `load_policies()` may be changed |
| `binaryClassification.py` | Binary classification | Implement `classify_binary()` |
| `generateIOCReport.py` | IOC report | Implement `generate_report()` |
| `warmUp.py` | Optional one-off setup before the tasks run | Implement `warm_up()` if needed |
| `requirements.txt` | Python dependencies, with pinned versions | Uncomment every package your pipeline needs |
| Your model files | Trained models, if your pipeline uses any, saved next to the template files | Add your model files, named as in [What to submit](#what-to-submit) (there is no `models/` folder) |

## Python version and packages

Your pipeline is run with **Python 3.12**. The starter `requirements.txt` lists every package you may use, each pinned to the version to use. Uncomment the ones your pipeline needs and keep their versions. `numpy` and `pandas` are already uncommented because `main.py` needs them.

Only the packages listed in your `requirements.txt` are installed when your submission is run. A model saved with one version of a package may not load with another, so train and save your models with the same versions that you list.

If your pipeline uses an LLM, `requirements.txt` contains commented-out lines for `llama-cpp-python` that install a prebuilt CPU build. Uncomment them if you need them.

## How your pipeline is run

Your submission is run with exactly this command:

```
python main.py --input <packets.csv> --policies <policy.yaml> --output <output_dir>
```

- The input CSV has the same feature columns as the labelled dataset.
- The ground-truth columns `Label`, `attack_cat` and `verdict` are removed before any of your code runs.
- Every packet is given a `packet_id`: its 0-based row number in the input CSV. This replaces any `packet_id` column already in the file.
- The run writes these files to `<output_dir>`:
  - `predictions.csv`: one row per packet, with the outputs of the three analysis tasks and the final action;
  - `run_metadata.json`: task order, settings, final action counts, timings and the list of model files in your submission folder;
  - your IOC report file(s).

## Interface requirements

`main.py` checks the output of every analysis task. If an output does not meet its requirements, the run stops with an error.

### `main.py`

You may edit **only** the `STUDENT CONFIG` block:

| Setting | Requirement |
|---|---|
| `PIPELINE_ORDER` | Any order of `"multiclass"`, `"policy"` and `"binary"`. Each must appear exactly once. |
| `RUN_WARM_UP` | `True` or `False`. Controls whether `warm_up()` is called. |
| `SKIP_CLASSIFICATION_FOR_DENIED` | `True` or `False`. A testing flag; be careful if you enable it in your submitted pipeline. When `True`, a classification task that runs after policy checking receives only the packets that were not denied, and its prediction columns are empty for denied packets. This saves time, but empty predictions count as wrong, and the IOC report then has no category for those packets. |
| `resolve_conflict()` | Called only for packets that were not denied. Must return `"PERMIT"` or `"DROP"`. |
| `CONFLICT_RULE_DESCRIPTION` | Required. Describe the rule implemented in `resolve_conflict()` and justify it. |

### `multiClassClassification.py`

`classify_multiclass(packets, context)` must return a pandas DataFrame with exactly one row per input packet and these columns:

| Column | Values |
|---|---|
| `packet_id` | Copied from the input |
| `attack_cat_pred` | One of `Normal`, `Generic`, `Exploits`, `Fuzzers`, `Reconnaissance`, `Analysis`, `Backdoor`, `Shellcode`, `Worms` (exact spelling). DoS is not a category in this project. |
| `multiclass_confidence` | A number in [0, 1], or NaN/None if not available |

### `checkPolicy.py`

`check_policy(packets, context)` must return a pandas DataFrame with exactly one row per input packet and these columns:

| Column | Values |
|---|---|
| `packet_id` | Copied from the input |
| `policy_decision` | `"DENY"` or `"ALLOW"` |
| `violated_policy` | ID(s) of the violated policies, separated by `;`, or `""` if none |
| `policy_reason` | Short human-readable reason, or `""` if none |

`load_policies(path)` reads the policy document. Its return value is available to all modules as `context["policies"]`. You may change what it returns. By default it returns the raw text of the file; if you parse the YAML with PyYAML, add `pyyaml` to `requirements.txt`.

Each entry in `policy.yaml` has a `policy_id`, a description (`policy`), a `transport` and a list of `ports`. A packet violates a policy when both of these are true:

- its `proto` matches `transport`, ignoring case (`policy.yaml` uses `TCP`; the packets use `tcp`);
- its source port (`sport`) **or** its destination port (`dsport`) is one of the listed `ports`.

An entry in `ports` is either a single port or a range such as `"6660-6669"`, which includes both ends. Use the `policy_id` values in `violated_policy`. Remember that `sport` and `dsport` use every format that appears in UNSW-NB15 (see [The dataset](#the-dataset)).

### `binaryClassification.py`

`classify_binary(packets, context)` must return a pandas DataFrame with exactly one row per input packet and these columns:

| Column | Values |
|---|---|
| `packet_id` | Copied from the input |
| `binary_pred` | `0` (normal) or `1` (attack) |
| `binary_confidence` | A number in [0, 1], or NaN/None if not available |

### `generateIOCReport.py`

`generate_report(results, output_dir, context)` must:

- write the IOC report, in the required format, to `output_dir`;
- return a list of the paths of the files it wrote.

`results` contains one row per packet (sorted by `packet_id`) with these columns:

- all input columns (without the ground-truth columns);
- all columns returned by the three analysis tasks;
- `multiclass_action` and `binary_action`: `"PERMIT"`, `"DROP"`, or `""` if the packet was skipped;
- `final_action`: `"DENY"`, `"PERMIT"` or `"DROP"`.

#### IOC report format

The report is a single `.json` file in `output_dir`, with any name except `run_metadata.json`. If you write more than one, the first `.json` path you return is graded.

The file holds one JSON array, with one entry for every packet whose `final_action` is `DROP` or `DENY`. Packets with `PERMIT` get no entry. Each entry has exactly this structure:

```json
[
  {
    "verdict": "drop",
    "stix": {
      "type": "bundle",
      "objects": [
        {
          "type": "network-traffic",
          "src_ip": "203.0.113.210",
          "dst_ip": "10.20.0.53",
          "src_port": 39720,
          "dst_port": 27950,
          "protocol": "tcp",
          "timestamp": "2026-10-27T00:11:34.227Z",
          "packet_index": 0
        },
        {
          "type": "indicator",
          "category": "Fuzzers",
          "policy_rule": null,
          "severity": "medium",
          "summary": "One or two sentences explaining why this packet was flagged."
        }
      ]
    }
  }
]
```

| Field | Value |
|---|---|
| `verdict` | `"drop"` or `"deny"` (lowercase), from `final_action` |
| `src_ip`, `dst_ip` | The `srcip` and `dstip` columns |
| `src_port`, `dst_port` | The `sport` and `dsport` columns, as integers |
| `protocol` | The `proto` column, unchanged |
| `timestamp` | The `timestamp` column, unchanged |
| `packet_index` | The `packet_id` column, as an integer |
| `category` | `attack_cat_pred`, or `null` if there is no attack category. Use `null`, not `"Normal"` or `""`, when the prediction is `Normal` or the packet was skipped. |
| `policy_rule` | The `violated_policy` value as a string, such as `"POL-1"`. Required on `deny` entries, and `null` on `drop` entries. |
| `severity` | `"low"`, `"medium"` or `"high"`, from the table below |
| `summary` | A non-empty description of the packet and why it was flagged |

| Entry | `severity` |
|---|---|
| `deny` with an attack category | `high` |
| `deny` with `category` `null` | `low` |
| `drop` with `Exploits`, `Backdoor`, `Shellcode` or `Worms` | `high` |
| `drop` with `Fuzzers` or `Generic` | `medium` |
| `drop` with `Analysis` or `Reconnaissance` | `low` |

### `warmUp.py`

`warm_up(context)` is called once before the analysis tasks run, if `RUN_WARM_UP` is `True`. It must return the context dictionary. Its run time is recorded separately from the tasks, but it still counts toward your efficiency (see [How your work is measured](#how-your-work-is-measured)).

### Shared context

Every function receives the same `context` dictionary. It contains:

| Key | Contents |
|---|---|
| `policies` | The return value of `load_policies()` |
| `output_dir` | Path of the output directory |
| `stage_results` | Read-only copies of the outputs of the analysis tasks that have already run, keyed by `"multiclass"`, `"policy"` and `"binary"` |

It also contains any keys you add in `warm_up()`. Changes made to `stage_results` are ignored.

## What is allowed

- Any one approach for each of the four tasks: hand-written rules (Python code), one machine-learning model of any type that you trained yourself, or one LLM. You may not combine approaches within a task, but different tasks may use different approaches.
- Any of the Python packages listed in the starter `requirements.txt`, at the versions given there.
- Additional Python modules and other files in your submission folder.
- Any order of the three analysis tasks, and any use of earlier tasks' results in later tasks.
- Running `multiClassClassification.py`, `checkPolicy.py` and `binaryClassification.py` on their own for testing (see the usage line at the top of each file). Each one checks its output against the same interface requirements that `main.py` enforces.

## Trained models

These rules apply only if your pipeline uses trained models:

- All training and fine-tuning must be completed **before** you submit. No training or fine-tuning may happen while the pipeline runs.
- Every model must be saved in your submission folder, next to the template files, and loaded from there by its full name, for example `MODELS_DIR / "abc123_binaryClassification.onnx"` (`MODELS_DIR` in each module is that folder).
- Every file in your submission folder except `.py` files, `requirements.txt`, `token.txt` and README files counts as a model file. It must be named `<netid>_<task>.<extension>`, and each task can have at most one (see [What to submit](#what-to-submit)). Do not leave datasets or other large files in the folder.
- **Machine-learning models** may be of any type you choose, as long as you trained them yourself. Each one must be saved in a model-storage format (for example `.json`, `.joblib` or `.onnx`) that can be loaded with the packages listed in your `requirements.txt`, and each model file can be **no larger than 12 MB**. A submission with any model file larger than 12 MB scores 0. If your model needs preprocessing (for example, encoding text columns such as `proto`), save that preprocessing inside the same model file, as you did in the Random Forest assignment.
- **LLMs** must be fine-tuned by you, saved in **GGUF** format (`.gguf`), and can be no larger than 850 MB and no more than 350M parameters, including embeddings. Each LLM must be a single `.gguf` file. A submission with a larger LLM scores 0.

The base-model must be from:
- LiquidAI (LFM2.5 & D1 series)
- Google Gemma Series
- Meta LLama
- IBM Granite

No other models are permitted. We do recommend sticking with what you know and use your project time wisely. You MUST start with an approved base-model and fine-tune yourself.
The models must run in the system as is: only the packages listed in your `requirements.txt` are installed (see [Python version and packages](#python-version-and-packages)). It's possible some of the approved models will not work. One thing we do know is that the LiquidAI models work from your midterm.

## What is not allowed

These rules are not open to exceptions.

- Editing `main.py` outside the `STUDENT CONFIG` block.
- Renaming the template files, or renaming or changing the parameters of the required functions.
- Changing the command-line arguments, the output file names, the required output columns, their allowed values or the list of attack categories.
- Using the ground-truth labels of the test data in any way, including obtaining them from any other source.
- Training or fine-tuning any model while the pipeline runs.
- Using a model that is not saved in your submission folder, including downloading a model at run time or calling a hosted model service.
- Using an LLM or an LDM larger than 850 MB or with more than 350M parameters.
- Using a machine-learning model whose file is larger than 12 MB, or that cannot be loaded with the packages listed in your `requirements.txt`.
- Using more than one rule set or model for a task.
- Including passwords, API keys or other credentials in your submission.
- Calling ANY external service.

## What to submit

Upload every file **individually**, not as a zip file, on both the Web-Portal and Gradescope. Put your NetID in front of every file name except `requirements.txt` and `token.txt`:

| File | Upload as |
|---|---|
| Each template file, and any other `.py` file | `<netid>_<file name>`, for example `abc123_main.py` |
| `requirements.txt` | `requirements.txt` |
| Each trained model, if any | `<netid>_<task>.<extension>`, for example `abc123_binaryClassification.onnx` |
| `token.txt` (Gradescope only) | `token.txt` |

A model's `<task>` is the module that uses it: `multiClassClassification`, `checkPolicy`, `binaryClassification` or `generateIOCReport`. Each task can have at most one model file.

For the NetID `abc123`, a submission with one model looks like this:
### For Web-Portal:
```
abc123_main.py
abc123_multiClassClassification.py
abc123_checkPolicy.py
abc123_binaryClassification.py
abc123_generateIOCReport.py
abc123_warmUp.py
requirements.txt
abc123_binaryClassification.onnx    # your trained models, if any
```

### For Gradescope:
```
abc123_main.py
abc123_multiClassClassification.py
abc123_checkPolicy.py
abc123_binaryClassification.py
abc123_generateIOCReport.py
abc123_warmUp.py
requirements.txt
token.txt
```

Before your pipeline runs, the NetID prefix is removed from every `.py` file, so your modules still import each other by their plain names (`import checkPolicy`). Model files keep the names you upload, so load each model by that name, for example `MODELS_DIR / "abc123_binaryClassification.onnx"`. While you work, keep your `.py` files under their plain names and give your model files their final names. Add the prefix to the `.py` files when you upload them.

A submission scores 0 if any of these is true:

- a file other than `requirements.txt` or `token.txt` does not start with your NetID;
- the files use more than one NetID;
- a model is not named `<netid>_<task>.<extension>`;
- a task has more than one model file.

Your pipeline must run from a fresh Python 3.12 environment after `pip install -r requirements.txt`, using the command shown in [How your pipeline is run](#how-your-pipeline-is-run).

## Deadlines

- **Deadline to Upload Submission on Web-Portal:** 16 December, 2026 
- **Deadline to Upload Submission on Gradescope:** 17 December, 2026