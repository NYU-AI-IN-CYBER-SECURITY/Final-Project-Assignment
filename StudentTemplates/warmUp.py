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

  * Save every one of them in your submission folder, next to the template files (MODELS_DIR is that folder; there is no models/ subfolder):
      - machine-learning models: any type you trained yourself, saved as .onnx,
        .joblib, .pkl, .ubj or .json so they load with the packages in
        requirements.txt, no larger than 12 MB each;
      - fine-tuned LLMs: GGUF format (.gguf), at most 850 MB and 350M parameters each.
    All model files together can be no larger than 3.4 GB. A task may use several.

  * Name each model file <netid>_<task>_<name>.<extension>, where the task is multiClassClassification, checkPolicy, binaryClassification or generateIOCReport and <name> uses only letters, digits and hyphens, e.g. abc123_binaryClassification_rf.onnx. 
    Load it by that name: it keeps it when you upload. 
    Only the .py files get the netid prefix at upload time, and it is removed again before your pipeline runs.
    
  * main.py lists your model files in run_metadata.json, and lists every other file in the folder (datasets, notebooks, output folders, ...) as extra_files:
      those are not part of a production-ready submission, and uploading any of them to the portal deducts 5 points.
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
