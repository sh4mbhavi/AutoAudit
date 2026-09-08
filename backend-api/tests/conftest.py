"""Load the shared CI guard within this project's pytest discovery boundary."""

import importlib.util
from pathlib import Path

_path = (
    Path(__file__).resolve().parents[2] / "tools" / "ci" / "integration_requirements.py"
)
_spec = importlib.util.spec_from_file_location(
    "autoaudit_integration_requirements", _path
)
_requirements = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_requirements)
pytest_sessionstart = _requirements.pytest_sessionstart
