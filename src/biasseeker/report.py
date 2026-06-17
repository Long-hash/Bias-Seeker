from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .environment import capture_environment
from .paths import ProjectPaths
from .results import generate_result_tables
from .scheduler import summarize_tasks
from .state import AWAITING_MANUAL_FIX, COMPLETED, DOWNLOAD_FAILED, FAILED_STAGE, PipelineState


def generate_reports(paths: ProjectPaths, state: PipelineState, datasets_config: dict[str, Any], experiments: dict[str, Any]) -> tuple[Path, Path]:
    paths.ensure()
    main = paths.reports / "reproduction_report.md"
    app = paths.reports / "application_classification_results.md"
    datasets = datasets_config.get("datasets", [])
    tasks = state.tasks()
    env_lock = capture_environment(paths)
    result_tables = generate_result_tables(paths, datasets, experiments)
    _write_main_report(main, paths, tasks, datasets, experiments, result_tables, env_lock)
    _write_application_report(app, paths, tasks, datasets, experiments, result_tables)
    return main, app


def _write_main_report(
    path: Path,
    paths: ProjectPaths,
    tasks: list[dict[str, Any]],
    datasets: list[dict[str, Any]],
    experiments: dict[str, Any],
    result_tables: dict[str, str],
    env_lock: Path,
) -> None:
    summary = summarize_tasks(tasks)
    with path.open("w", encoding="utf-8") as handle:
        handle.write("# BiasSeeker Reproduction Report\n\n")
        handle.write("This report is generated from the resumable AutoDL pipeline state. It records completed work, pending manual fixes, and failed stages without silently skipping experiments.\n\n")
        handle.write("## Scope\n\n")
        handle.write("- Reproduce the paper settings with both NetMamba and Decision Tree.\n")
        handle.write("- Preserve combined model comparison tables and per-model independent result tables.\n")
        handle.write("- Keep encrypted application classification as a focused result area.\n\n")
        handle.write("## Task Summary\n\n")
        for status, count in sorted(summary.items()):
            handle.write(f"- `{status}`: {count}\n")
        handle.write(f"\n## Environment Snapshot\n\n- Environment lock: `{env_lock}`\n")
        handle.write("\n## Dataset Status\n\n")
        for dataset in datasets:
            handle.write(f"### {dataset['name']} (`{dataset['id']}`)\n\n")
            handle.write(f"- Task: `{dataset.get('task')}`\n")
            handle.write(f"- Paper role: `{dataset.get('paper_role')}`\n")
            handle.write(f"- Raw path: `{paths.raw / dataset['id']}`\n")
            if dataset.get("mitigation"):
                handle.write(f"- Paper mitigation stats: `{json.dumps(dataset['mitigation'], ensure_ascii=False)}`\n")
            _write_dataset_task_table(handle, tasks, dataset["id"])
            handle.write("\n")
        handle.write("## Completed Results\n\n")
        _write_task_list(handle, tasks, {COMPLETED})
        handle.write("\n## Pending Manual Fixes\n\n")
        _write_task_list(handle, tasks, {AWAITING_MANUAL_FIX, DOWNLOAD_FAILED, FAILED_STAGE})
        handle.write("\n## Model Result Tables\n\n")
        handle.write(f"- Combined model table: `{result_tables['combined']}`\n")
        handle.write(f"- NetMamba-only table: `{result_tables['netmamba']}`\n")
        handle.write(f"- DecisionTree-only table: `{result_tables['decision_tree']}`\n\n")
        handle.write("Rows whose metrics are not available are marked `pending`, not skipped.\n\n")
        handle.write("## Unresolved Reproduction Details\n\n")
        handle.write("- Original paper does not disclose all random seeds, exact sampled class IDs, private preprocessing scripts, or NetMamba checkpoint hashes.\n")
        handle.write("- NetMamba must be re-pre-trained for this paper reproduction; the original NetMamba paper checkpoint is only a setup/reference artifact.\n")
        handle.write("- NetMamba inputs must use bidirectional session flows and mitigation-specific header handling, matching the BiasSeeker paper rather than the original NetMamba paper setup.\n")
        handle.write("- Decision Tree feature matrices are derived automatically from normalized packet fields when labels can be inferred or provided.\n")


def _write_application_report(
    path: Path,
    paths: ProjectPaths,
    tasks: list[dict[str, Any]],
    datasets: list[dict[str, Any]],
    experiments: dict[str, Any],
    result_tables: dict[str, str],
) -> None:
    app_datasets = [dataset for dataset in datasets if dataset.get("application_focus") or dataset.get("task") == "encrypted_application"]
    with path.open("w", encoding="utf-8") as handle:
        handle.write("# Encrypted Application Classification Focus\n\n")
        handle.write("This focused report isolates encrypted application classification datasets and model outcomes.\n\n")
        handle.write("## Focus Datasets\n\n")
        for dataset in app_datasets:
            handle.write(f"- `{dataset['id']}`: {dataset['name']} ({dataset.get('paper_role')})\n")
        handle.write("\n## Dataset Task Status\n\n")
        for dataset in app_datasets:
            handle.write(f"### {dataset['name']} (`{dataset['id']}`)\n\n")
            _write_dataset_task_table(handle, tasks, dataset["id"])
            handle.write("\n")
        handle.write("## Required Application-Specific Outputs\n\n")
        handle.write("- AMI top-k tables for CrossPlatform Android, CrossPlatform iOS, CrossNet2021, CSTNET-TLS1.3, and CipherSpectrum.\n")
        handle.write("- Relative artifact comparison for `tsval/time_relative`, `seq_raw/seq`, and `ack_raw/ack`.\n")
        handle.write("- CrossNet-A/B TCP Window Size KDE and KL divergence analysis.\n")
        handle.write("- CrossNet2021 and CSTNET-TLS1.3 combined, NetMamba-only, and DecisionTree-only mitigation tables.\n\n")
        handle.write("## Application Model Tables\n\n")
        handle.write(f"- Combined: `{result_tables['application_combined']}`\n")
        handle.write(f"- NetMamba-only: `{result_tables['application_netmamba']}`\n")
        handle.write(f"- DecisionTree-only: `{result_tables['application_decision_tree']}`\n\n")
        handle.write("## Pending Manual Fixes For Application Classification\n\n")
        app_ids = {dataset["id"] for dataset in app_datasets}
        _write_task_list(handle, [task for task in tasks if task.get("key", {}).get("dataset") in app_ids], {AWAITING_MANUAL_FIX, DOWNLOAD_FAILED, FAILED_STAGE})


def _write_dataset_task_table(handle: Any, tasks: list[dict[str, Any]], dataset_id: str) -> None:
    handle.write("\n| Stage | Model | Strategy | Status | Message |\n")
    handle.write("| --- | --- | --- | --- | --- |\n")
    dataset_tasks = [task for task in tasks if task.get("key", {}).get("dataset") == dataset_id]
    for task in dataset_tasks:
        key = task.get("key", {})
        message = str(task.get("message", "")).replace("\n", " ")
        handle.write(
            f"| `{key.get('stage')}` | `{key.get('model') or ''}` | `{key.get('strategy') or ''}` | `{task.get('status')}` | {message} |\n"
        )


def _write_task_list(handle: Any, tasks: list[dict[str, Any]], statuses: set[str]) -> None:
    selected = [task for task in tasks if task.get("status") in statuses]
    if not selected:
        handle.write("No tasks in this category.\n")
        return
    for task in selected:
        key = task.get("key", {})
        failure = task.get("failure") or {}
        manifest = failure.get("manifest") or ""
        handle.write(
            f"- `{key.get('dataset')}::{key.get('stage')}::{key.get('model') or ''}::{key.get('strategy') or ''}` "
            f"status `{task.get('status')}`: {task.get('message', '')}"
        )
        if manifest:
            handle.write(f" Manifest: `{manifest}`")
        handle.write("\n")
