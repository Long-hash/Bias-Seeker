from __future__ import annotations

from typing import Any, Iterable

from .paths import ProjectPaths
from .stages import (
    STAGE_RUNNERS,
    run_netmamba_pretrain,
    run_mitigation_prepare,
    run_split,
    run_train_eval,
)
from .state import COMPLETED, PipelineState, TaskKey


def build_tasks(datasets: list[dict[str, Any]], experiments: dict[str, Any]) -> list[TaskKey]:
    tasks: list[TaskKey] = []
    base_stages = experiments.get("stages", [])
    strategies = experiments.get("mitigation_strategies", [])
    models = [name for name, cfg in experiments.get("models", {}).items() if cfg.get("enabled", True)]
    netmamba_cfg = experiments.get("models", {}).get("netmamba", {})

    if netmamba_cfg.get("enabled", True) and netmamba_cfg.get("pretrain_required"):
        tasks.append(TaskKey(dataset="__global__", stage="netmamba_pretrain_prepare"))
        tasks.append(TaskKey(dataset="__global__", stage="netmamba_pretrain"))

    for dataset in datasets:
        dataset_id = dataset["id"]
        for stage in base_stages:
            tasks.append(TaskKey(dataset=dataset_id, stage=stage))
        tasks.append(TaskKey(dataset=dataset_id, stage="derive_inputs"))
        if dataset.get("mitigation"):
            tasks.append(TaskKey(dataset=dataset_id, stage="split"))
            for strategy in strategies:
                tasks.append(TaskKey(dataset=dataset_id, stage="mitigation_prepare", strategy=strategy))
                for model in models:
                    tasks.append(TaskKey(dataset=dataset_id, stage="train_eval", model=model, strategy=strategy))
    return tasks


def initialize_state(state: PipelineState, datasets: list[dict[str, Any]], experiments: dict[str, Any]) -> None:
    for task in build_tasks(datasets, experiments):
        state.ensure_task(task)
    state.save()


def dependencies_completed(state: PipelineState, key: TaskKey, experiments: dict[str, Any]) -> bool:
    if key.stage == "download":
        return True
    if key.stage == "netmamba_pretrain":
        if not _is_completed(state, TaskKey(dataset="__global__", stage="netmamba_pretrain_prepare")):
            return False
        return True
    if key.stage == "netmamba_pretrain_prepare":
        for dataset_id in experiments.get("netmamba_pretrain_datasets", []):
            if not _is_completed(state, TaskKey(dataset=dataset_id, stage="derive_inputs")):
                return False
        return True
    if key.stage in {"verify_data", "parse", "normalize", "ami_detection", "split"}:
        order = ["download", "verify_data", "parse", "normalize", "derive_inputs", "ami_detection", "split"]
        previous = order[order.index(key.stage) - 1]
        return _is_completed(state, TaskKey(dataset=key.dataset, stage=previous))
    if key.stage == "derive_inputs":
        return _is_completed(state, TaskKey(dataset=key.dataset, stage="normalize"))
    if key.stage == "mitigation_prepare":
        return _is_completed(state, TaskKey(dataset=key.dataset, stage="split"))
    if key.stage == "train_eval":
        if key.model == "netmamba":
            netmamba_cfg = experiments.get("models", {}).get("netmamba", {})
            if netmamba_cfg.get("pretrain_required") and not _is_completed(state, TaskKey(dataset="__global__", stage="netmamba_pretrain")):
                return False
        return _is_completed(state, TaskKey(dataset=key.dataset, stage="mitigation_prepare", strategy=key.strategy))
    return True


def _is_completed(state: PipelineState, key: TaskKey) -> bool:
    task = state.get_task(key)
    return bool(task and task.get("status") == COMPLETED)


def run_pipeline(paths: ProjectPaths, state: PipelineState, datasets: list[dict[str, Any]], experiments: dict[str, Any]) -> None:
    initialize_state(state, datasets, experiments)
    dataset_map = {dataset["id"]: dataset for dataset in datasets}
    for key in build_tasks(datasets, experiments):
        current = state.get_task(key)
        if current and current.get("status") == COMPLETED:
            continue
        if not dependencies_completed(state, key, experiments):
            continue
        state.mark_running(key)
        if key.stage in STAGE_RUNNERS:
            dataset = dataset_map[key.dataset]
            STAGE_RUNNERS[key.stage](paths, state, dataset)
        elif key.stage == "split":
            dataset = dataset_map[key.dataset]
            run_split(paths, state, dataset, experiments)
        elif key.stage == "mitigation_prepare":
            dataset = dataset_map[key.dataset]
            run_mitigation_prepare(paths, state, dataset, key.strategy or "")
        elif key.stage == "train_eval":
            dataset = dataset_map[key.dataset]
            run_train_eval(paths, state, dataset, experiments, key.model or "", key.strategy or "")
        elif key.stage == "derive_inputs":
            dataset = dataset_map[key.dataset]
            from .stages import run_derive_inputs

            run_derive_inputs(paths, state, dataset, experiments)
        elif key.stage == "netmamba_pretrain":
            run_netmamba_pretrain(paths, state, experiments)
        elif key.stage == "netmamba_pretrain_prepare":
            from .stages import run_netmamba_pretrain_prepare

            run_netmamba_pretrain_prepare(paths, state, experiments)


def summarize_tasks(tasks: Iterable[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for task in tasks:
        status = task.get("status", "unknown")
        summary[status] = summary.get(status, 0) + 1
    return summary
