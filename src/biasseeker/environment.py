from __future__ import annotations

import importlib.metadata
import json
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from .paths import ProjectPaths


PACKAGES = ["numpy", "pandas", "scikit-learn", "torch", "tqdm"]


def capture_environment(paths: ProjectPaths) -> Path:
    payload: dict[str, Any] = {
        "python": sys.version,
        "executable": sys.executable,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "packages": {},
        "binaries": {},
        "gpu": _run_optional(["nvidia-smi", "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader"]),
    }
    for package in PACKAGES:
        try:
            payload["packages"][package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            payload["packages"][package] = None
    for binary in ["tshark", "python", "nvidia-smi"]:
        payload["binaries"][binary] = shutil.which(binary)
    output = paths.reports / "env.lock.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return output


def _run_optional(command: list[str]) -> str | None:
    if shutil.which(command[0]) is None:
        return None
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip()
