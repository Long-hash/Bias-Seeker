from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any


def compute_top_ami(packet_fields_path: Path, labels_path: Path, top_k: int = 10) -> list[dict[str, Any]]:
    try:
        from sklearn.metrics import adjusted_mutual_info_score
    except ImportError as exc:  # pragma: no cover - depends on AutoDL environment
        raise RuntimeError("scikit-learn is required for AMI computation.") from exc

    labels = _load_labels(labels_path)
    rows = []
    with packet_fields_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            rows.append(json.loads(line))
    if not rows:
        raise ValueError("packet_fields.jsonl contains no rows.")

    y = []
    aligned_rows = []
    for row in rows:
        key = str(row.get("packet_index"))
        if key in labels:
            y.append(labels[key])
            aligned_rows.append(row)
    if not aligned_rows:
        raise ValueError("No packet rows could be aligned with labels.")

    ignored = {"dataset", "source_file", "packet_index"}
    features = sorted(set().union(*(row.keys() for row in aligned_rows)) - ignored)
    scores: list[dict[str, Any]] = []
    for feature in features:
        x = [str(row.get(feature, "__MISSING__")) for row in aligned_rows]
        if len(set(x)) <= 1:
            continue
        score = adjusted_mutual_info_score(y, x)
        scores.append({"feature": feature, "ami": f"{score:.10f}"})
    scores.sort(key=lambda row: float(row["ami"]), reverse=True)
    return scores[:top_k]


def _load_labels(path: Path) -> dict[str, str]:
    labels: dict[str, str] = {}
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("labels.csv has no header.")
        if "label" not in reader.fieldnames:
            raise ValueError("labels.csv must include a label column.")
        id_column = "packet_index" if "packet_index" in reader.fieldnames else "session_id" if "session_id" in reader.fieldnames else None
        if not id_column:
            raise ValueError("labels.csv must include packet_index or session_id.")
        for row in reader:
            labels[str(row[id_column])] = row["label"]
    return labels
