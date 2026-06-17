from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .paths import ProjectPaths


def generate_result_tables(paths: ProjectPaths, datasets: list[dict[str, Any]], experiments: dict[str, Any]) -> dict[str, str]:
    paths.tables.mkdir(parents=True, exist_ok=True)
    rows = collect_metric_rows(paths, datasets, experiments)
    combined = paths.tables / "table_iii_combined.csv"
    netmamba = paths.tables / "table_iii_netmamba_only.csv"
    decision_tree = paths.tables / "table_iii_decision_tree_only.csv"
    app_combined = paths.tables / "application_table_combined.csv"
    app_netmamba = paths.tables / "application_table_netmamba_only.csv"
    app_decision_tree = paths.tables / "application_table_decision_tree_only.csv"

    _write_rows(combined, rows)
    _write_rows(netmamba, [row for row in rows if row["model"] == "netmamba"])
    _write_rows(decision_tree, [row for row in rows if row["model"] == "decision_tree"])

    app_ids = {dataset["id"] for dataset in datasets if dataset.get("application_focus") or dataset.get("task") == "encrypted_application"}
    app_rows = [row for row in rows if row["dataset"] in app_ids]
    _write_rows(app_combined, app_rows)
    _write_rows(app_netmamba, [row for row in app_rows if row["model"] == "netmamba"])
    _write_rows(app_decision_tree, [row for row in app_rows if row["model"] == "decision_tree"])

    return {
        "combined": str(combined),
        "netmamba": str(netmamba),
        "decision_tree": str(decision_tree),
        "application_combined": str(app_combined),
        "application_netmamba": str(app_netmamba),
        "application_decision_tree": str(app_decision_tree),
    }


def collect_metric_rows(paths: ProjectPaths, datasets: list[dict[str, Any]], experiments: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    strategies = experiments.get("mitigation_strategies", [])
    models = [name for name, cfg in experiments.get("models", {}).items() if cfg.get("enabled", True)]
    for dataset in datasets:
        if not dataset.get("mitigation"):
            continue
        for strategy in strategies:
            for model in models:
                metrics = _metric_path(paths, dataset["id"], strategy, model)
                if metrics.exists():
                    try:
                        payload = json.loads(metrics.read_text(encoding="utf-8"))
                        rows.append(
                            {
                                "dataset": dataset["id"],
                                "dataset_name": dataset["name"],
                                "task": dataset.get("task", ""),
                                "strategy": strategy,
                                "model": model,
                                "status": "completed",
                                "accuracy": payload.get("accuracy", ""),
                                "metrics_path": str(metrics),
                            }
                        )
                    except json.JSONDecodeError:
                        rows.append(_pending_row(dataset, strategy, model, "invalid_metrics_json", str(metrics)))
                else:
                    rows.append(_pending_row(dataset, strategy, model, "pending", str(metrics)))
    return rows


def _metric_path(paths: ProjectPaths, dataset_id: str, strategy: str, model: str) -> Path:
    if model == "decision_tree":
        return paths.tables / dataset_id / f"{strategy}_decision_tree_metrics.json"
    return paths.tables / dataset_id / f"{strategy}_{model}_metrics.json"


def _pending_row(dataset: dict[str, Any], strategy: str, model: str, status: str, metrics_path: str) -> dict[str, Any]:
    return {
        "dataset": dataset["id"],
        "dataset_name": dataset["name"],
        "task": dataset.get("task", ""),
        "strategy": strategy,
        "model": model,
        "status": status,
        "accuracy": "",
        "metrics_path": metrics_path,
    }


def _write_rows(path: Path, rows: list[dict[str, Any]]) -> None:
    fieldnames = ["dataset", "dataset_name", "task", "strategy", "model", "status", "accuracy", "metrics_path"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
