from __future__ import annotations

import importlib.util
import platform
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    ok: bool
    detail: str


def run_doctor() -> list[Check]:
    checks = [
        Check("python", sys.version_info >= (3, 11), platform.python_version()),
        Check("platform", True, platform.platform()),
        Check("web-extra", importlib.util.find_spec("fastapi") is not None, "FastAPI installed" if importlib.util.find_spec("fastapi") else "Install socmind[web]"),
        Check("sigma-extra", importlib.util.find_spec("yaml") is not None, "PyYAML installed" if importlib.util.find_spec("yaml") else "Install socmind[sigma]"),
        Check("rules-directory", Path("detections").is_dir(), str(Path("detections").resolve())),
        Check("examples-directory", Path("examples").is_dir(), str(Path("examples").resolve())),
    ]
    return checks


def doctor_payload() -> list[dict]:
    return [asdict(item) for item in run_doctor()]
