from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PENDING_DOWNLOAD = "pending_download"
DOWNLOAD_FAILED = "download_failed"
AWAITING_MANUAL_FIX = "awaiting_manual_fix"
READY = "ready"
RUNNING = "running"
FAILED_STAGE = "failed_stage"
COMPLETED = "completed"

TERMINAL_FAILURES = {DOWNLOAD_FAILED, AWAITING_MANUAL_FIX, FAILED_STAGE}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class TaskKey:
    dataset: str
    stage: str
    model: str | None = None
    strategy: str | None = None

    def id(self) -> str:
        parts = [self.dataset, self.stage]
        if self.model:
            parts.append(self.model)
        if self.strategy:
            parts.append(self.strategy)
        return "::".join(parts)


class PipelineState:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data: dict[str, Any] = {
            "version": 1,
            "created_at": utc_now(),
            "updated_at": utc_now(),
            "tasks": {},
        }

    @classmethod
    def load(cls, path: Path) -> "PipelineState":
        state = cls(path)
        if path.exists():
            with path.open("r", encoding="utf-8") as handle:
                state.data = json.load(handle)
        return state

    def save(self) -> None:
        self.data["updated_at"] = utc_now()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(self.data, handle, indent=2, ensure_ascii=False, sort_keys=True)
        tmp.replace(self.path)

    def ensure_task(self, key: TaskKey, initial_status: str = READY) -> dict[str, Any]:
        task_id = key.id()
        tasks = self.data.setdefault("tasks", {})
        if task_id not in tasks:
            tasks[task_id] = {
                "key": asdict(key),
                "status": initial_status,
                "attempts": 0,
                "created_at": utc_now(),
                "updated_at": utc_now(),
                "artifacts": {},
                "message": "",
                "failure": None,
            }
        return tasks[task_id]

    def get_task(self, key: TaskKey) -> dict[str, Any] | None:
        return self.data.get("tasks", {}).get(key.id())

    def mark_running(self, key: TaskKey) -> None:
        task = self.ensure_task(key)
        task["status"] = RUNNING
        task["attempts"] = int(task.get("attempts", 0)) + 1
        task["updated_at"] = utc_now()
        task["failure"] = None
        self.save()

    def mark_completed(
        self,
        key: TaskKey,
        message: str = "",
        artifacts: dict[str, Any] | None = None,
    ) -> None:
        task = self.ensure_task(key)
        task["status"] = COMPLETED
        task["message"] = message
        task["updated_at"] = utc_now()
        task["failure"] = None
        if artifacts:
            task.setdefault("artifacts", {}).update(artifacts)
        self.save()

    def mark_failed(
        self,
        key: TaskKey,
        status: str,
        message: str,
        failure_manifest: str | None = None,
        artifacts: dict[str, Any] | None = None,
    ) -> None:
        if status not in TERMINAL_FAILURES:
            raise ValueError(f"Invalid failure status: {status}")
        task = self.ensure_task(key)
        task["status"] = status
        task["message"] = message
        task["updated_at"] = utc_now()
        task["failure"] = {
            "message": message,
            "manifest": failure_manifest,
            "time": utc_now(),
        }
        if artifacts:
            task.setdefault("artifacts", {}).update(artifacts)
        self.save()

    def tasks(self) -> list[dict[str, Any]]:
        return list(self.data.get("tasks", {}).values())
