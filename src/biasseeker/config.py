from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULT_DATASETS_CONFIG = Path("configs/datasets.json")
DEFAULT_EXPERIMENTS_CONFIG = Path("configs/experiments.json")


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_configs(
    datasets_path: Path = DEFAULT_DATASETS_CONFIG,
    experiments_path: Path = DEFAULT_EXPERIMENTS_CONFIG,
) -> tuple[dict[str, Any], dict[str, Any]]:
    return load_json(datasets_path), load_json(experiments_path)


def dataset_by_id(datasets_config: dict[str, Any], dataset_id: str) -> dict[str, Any]:
    for dataset in datasets_config.get("datasets", []):
        if dataset["id"] == dataset_id:
            return dataset
    raise KeyError(f"Unknown dataset: {dataset_id}")
