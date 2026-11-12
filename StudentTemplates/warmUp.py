"""
warmUp.py - Optional warm-up

main.py calls warm_up() once, before any analysis stage, when RUN_WARM_UP is True.
It is timed separately from the stages, so use it for any one-off setup your approach needs before processing packets.
Its run time still counts toward your pipeline's efficiency: it is part of your system.
If you need none, leave it as is.

Whatever you add to `context` is passed to every later stage.

`context` already contains:
    "policies"    - whatever checkPolicy.load_policies() returned
    "output_dir"  - Path of the output directory (only when run through main.py)
Later, main.py also adds "stage_results": the outputs of the stages that have run.

Trained models (applies only if your approach uses any, in any module):
  * Train or fine-tune them BEFORE submitting. The pipeline only loads saved files.
    No training or fine-tuning may happen when it runs.
  * Save every one of them in your submission folder, next to the template
    files (MODELS_DIR is that folder; there is no models/ subfolder):
      - machine-learning models: any type you trained yourself, saved in a
        model-storage format (e.g. .json, .joblib, .onnx) that loads with the
        packages in requirements.txt, no larger than 12 MB each;
      - fine-tuned LLMs: GGUF format (.gguf).
  * Every file in the folder except .py files, requirements.txt, token.txt and
    README files counts as a model file, and main.py lists them in run_metadata.json.
    Do not leave datasets or other large files in the folder.
  * Name each model <netid>_<task>.<extension>, at most one per task, where
    the task is multiClassClassification, checkPolicy, binaryClassification or
    generateIOCReport, e.g. abc123_binaryClassification.onnx. Load it by that
    name: it keeps it when you upload. Only the .py files get the netid prefix
    at upload time, and it is removed again before your pipeline runs.
"""

from __future__ import annotations

from pathlib import Path

# Folder of your submission, where trained models are saved (see above).
SUBMISSION_DIR = Path(__file__).parent
MODELS_DIR = SUBMISSION_DIR


def warm_up(context: dict) -> dict:
    """Do any one-off setup and return the (updated) context."""

    # TODO (optional): add your setup steps here.

    return context
