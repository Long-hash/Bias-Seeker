from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .state import TaskKey, utc_now


def write_failure(
    failures_root: Path,
    key: TaskKey,
    message: str,
    manual_action: str,
    details: dict[str, Any] | None = None,
) -> tuple[Path, Path]:
    task_dir = failures_root / key.dataset / key.stage
    if key.model:
        task_dir = task_dir / key.model
    if key.strategy:
        task_dir = task_dir / key.strategy
    task_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "task": {
            "dataset": key.dataset,
            "stage": key.stage,
            "model": key.model,
            "strategy": key.strategy,
        },
        "message": message,
        "manual_action": manual_action,
        "details": details or {},
        "created_at": utc_now(),
    }

    manifest_path = task_dir / "failure_manifest.json"
    report_path = task_dir / "failure_report.md"

    with manifest_path.open("w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, ensure_ascii=False, sort_keys=True)

    with report_path.open("w", encoding="utf-8") as handle:
        handle.write(f"# Failure: {key.id()}\n\n")
        handle.write(f"**Status:** requires manual attention\n\n")
        handle.write(f"**Reason:** {message}\n\n")
        handle.write(f"**Manual action:** {manual_action}\n\n")
        if details:
            handle.write("## Details\n\n")
            for name, value in details.items():
                handle.write(f"- `{name}`: `{value}`\n")

    return report_path, manifest_path
