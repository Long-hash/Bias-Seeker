from __future__ import annotations

import csv
import hashlib
import json
import shutil
import subprocess
import re
from pathlib import Path
from typing import Any

from .download import dataset_raw_dir, has_expected_files, run_download
from .failures import write_failure
from .paths import ProjectPaths
from .state import AWAITING_MANUAL_FIX, COMPLETED, FAILED_STAGE, PipelineState, TaskKey


PCAP_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


def pcap_files(raw_dir: Path) -> list[Path]:
    if not raw_dir.exists():
        return []
    return [path for path in raw_dir.rglob("*") if path.is_file() and path.suffix.lower() in PCAP_EXTENSIONS]


def mark_manual_failure(
    paths: ProjectPaths,
    state: PipelineState,
    key: TaskKey,
    message: str,
    action: str,
    details: dict[str, Any] | None = None,
    status: str = AWAITING_MANUAL_FIX,
) -> str:
    report, manifest = write_failure(paths.failures, key, message, action, details)
    state.mark_failed(key, status, message, str(manifest), {"failure_report": str(report)})
    return status


def run_verify_data(paths: ProjectPaths, state: PipelineState, dataset: dict[str, Any]) -> str:
    key = TaskKey(dataset=dataset["id"], stage="verify_data")
    raw_dir = dataset_raw_dir(paths, dataset)
    if not has_expected_files(paths, dataset):
        return mark_manual_failure(
            paths,
            state,
            key,
            "Expected dataset files are missing.",
            f"Place the configured files under {raw_dir} and rerun the pipeline.",
            {"raw_dir": str(raw_dir), "expected_files": dataset.get("expected_files", [])},
        )
    found_pcaps = pcap_files(raw_dir)
    if not found_pcaps:
        return mark_manual_failure(
            paths,
            state,
            key,
            "Dataset directory exists, but no pcap/pcapng/cap files were found.",
            f"Extract or place raw capture files under {raw_dir}; do not remove completed state files.",
            {"raw_dir": str(raw_dir)},
        )
    state.mark_completed(
        key,
        f"Found {len(found_pcaps)} packet capture file(s).",
        {"pcap_count": len(found_pcaps), "raw_dir": str(raw_dir)},
    )
    return COMPLETED


def run_parse(paths: ProjectPaths, state: PipelineState, dataset: dict[str, Any]) -> str:
    key = TaskKey(dataset=dataset["id"], stage="parse")
    raw_dir = dataset_raw_dir(paths, dataset)
    found_pcaps = pcap_files(raw_dir)
    if not found_pcaps:
        return mark_manual_failure(
            paths,
            state,
            key,
            "Cannot parse because no packet capture files are available.",
            f"Place pcap/pcapng/cap files under {raw_dir} and rerun the pipeline.",
            {"raw_dir": str(raw_dir)},
        )
    if shutil.which("tshark") is None:
        return mark_manual_failure(
            paths,
            state,
            key,
            "tshark is not installed or not on PATH.",
            "Install Wireshark/tshark on AutoDL, then rerun the pipeline.",
            {"install_hint": "apt-get install -y tshark"},
            status=FAILED_STAGE,
        )

    out_dir = paths.interim / dataset["id"] / "tshark_json"
    out_dir.mkdir(parents=True, exist_ok=True)
    parsed = []
    for capture in found_pcaps:
        output = out_dir / f"{capture.stem}.json"
        if output.exists() and output.stat().st_size > 0:
            parsed.append(output)
            continue
        log_path = paths.logs / f"{dataset['id']}_{capture.stem}_tshark.log"
        command = ["tshark", "-r", str(capture), "-T", "json", "-x"]
        with output.open("w", encoding="utf-8") as stdout, log_path.open("w", encoding="utf-8") as stderr:
            result = subprocess.run(command, stdout=stdout, stderr=stderr, text=True)
        if result.returncode != 0:
            return mark_manual_failure(
                paths,
                state,
                key,
                f"tshark failed for {capture.name}.",
                "Inspect the tshark log, repair or replace the capture file, then rerun the pipeline.",
                {"capture": str(capture), "log": str(log_path), "command": " ".join(command)},
                status=FAILED_STAGE,
            )
        parsed.append(output)
    state.mark_completed(key, f"Parsed {len(parsed)} capture file(s) with tshark.", {"parsed_files": [str(p) for p in parsed]})
    return COMPLETED


def flatten_layers(prefix: str, value: Any, row: dict[str, Any]) -> None:
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            next_prefix = f"{prefix}.{child_key}" if prefix else child_key
            flatten_layers(next_prefix, child_value, row)
    elif isinstance(value, list):
        if all(not isinstance(item, (dict, list)) for item in value):
            row[prefix] = "|".join(str(item) for item in value)
        else:
            for index, item in enumerate(value):
                flatten_layers(f"{prefix}.{index}", item, row)
    else:
        row[prefix] = value


def run_normalize(paths: ProjectPaths, state: PipelineState, dataset: dict[str, Any]) -> str:
    key = TaskKey(dataset=dataset["id"], stage="normalize")
    in_dir = paths.interim / dataset["id"] / "tshark_json"
    json_files = sorted(in_dir.glob("*.json"))
    if not json_files:
        return mark_manual_failure(
            paths,
            state,
            key,
            "No tshark JSON files found.",
            "Run or repair the parse stage, then rerun the pipeline.",
            {"expected_dir": str(in_dir)},
            status=FAILED_STAGE,
        )

    out_dir = paths.processed / dataset["id"]
    out_dir.mkdir(parents=True, exist_ok=True)
    output = out_dir / "packet_fields.jsonl"
    count = 0
    try:
        with output.open("w", encoding="utf-8") as handle:
            for json_path in json_files:
                with json_path.open("r", encoding="utf-8") as source:
                    packets = json.load(source)
                for packet_index, packet in enumerate(packets):
                    row: dict[str, Any] = {
                        "dataset": dataset["id"],
                        "source_file": json_path.name,
                        "packet_index": packet_index,
                    }
                    layers = packet.get("_source", {}).get("layers", {})
                    flatten_layers("", layers, row)
                    handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
                    count += 1
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        return mark_manual_failure(
            paths,
            state,
            key,
            f"Failed to flatten tshark JSON: {exc}",
            "Inspect the parsed JSON files, repair the parse output, then rerun the pipeline.",
            {"input_dir": str(in_dir), "output": str(output)},
            status=FAILED_STAGE,
        )
    if count == 0:
        return mark_manual_failure(
            paths,
            state,
            key,
            "Normalization produced zero packet rows.",
            "Verify that tshark JSON contains packet layers and rerun the pipeline.",
            {"output": str(output)},
            status=FAILED_STAGE,
        )
    state.mark_completed(key, f"Flattened {count} packet rows.", {"packet_fields": str(output), "packet_count": count})
    return COMPLETED


def run_ami_detection(paths: ProjectPaths, state: PipelineState, dataset: dict[str, Any]) -> str:
    key = TaskKey(dataset=dataset["id"], stage="ami_detection")
    packet_fields = paths.processed / dataset["id"] / "packet_fields.jsonl"
    labels = paths.processed / dataset["id"] / "labels.csv"
    if not packet_fields.exists():
        return mark_manual_failure(
            paths,
            state,
            key,
            "Cannot compute AMI because normalized packet fields are missing.",
            "Repair earlier stages and rerun the pipeline.",
            {"required": str(packet_fields)},
            status=FAILED_STAGE,
        )
    if not labels.exists():
        return mark_manual_failure(
            paths,
            state,
            key,
            "Label file is missing for AMI computation.",
            f"Create {labels} with at least packet/session identifiers and class labels, then rerun.",
            {"required": str(labels), "expected_columns": "packet_index,label or session_id,label"},
        )
    try:
        from .statistics import compute_top_ami

        top_rows = compute_top_ami(packet_fields, labels)
    except Exception as exc:  # pragma: no cover - dependency/data dependent
        return mark_manual_failure(
            paths,
            state,
            key,
            f"AMI computation failed: {exc}",
            "Inspect labels and normalized fields, install scikit-learn if needed, then rerun.",
            {"packet_fields": str(packet_fields), "labels": str(labels)},
            status=FAILED_STAGE,
        )

    out_dir = paths.tables / dataset["id"]
    out_dir.mkdir(parents=True, exist_ok=True)
    output = out_dir / "ami_top10.csv"
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["feature", "ami"])
        writer.writeheader()
        writer.writerows(top_rows)
    state.mark_completed(key, "Computed AMI top-10 features.", {"ami_top10": str(output)})
    return COMPLETED


def run_derive_inputs(paths: ProjectPaths, state: PipelineState, dataset: dict[str, Any], experiments: dict[str, Any]) -> str:
    key = TaskKey(dataset=dataset["id"], stage="derive_inputs")
    packet_fields = paths.processed / dataset["id"] / "packet_fields.jsonl"
    if not packet_fields.exists():
        return mark_manual_failure(
            paths,
            state,
            key,
            "Cannot derive intermediate inputs because packet_fields.jsonl is missing.",
            "Repair normalize stage and rerun.",
            {"required": str(packet_fields)},
            status=FAILED_STAGE,
        )

    output_root = paths.processed / dataset["id"] / "derived_inputs"
    netmamba_dir = output_root / "netmamba"
    decision_tree_path = output_root / "decision_tree_features.csv"
    labels_path = paths.processed / dataset["id"] / "labels.csv"

    try:
        records = _load_packet_records(packet_fields)
        labels = _load_labels(labels_path, records)
    except Exception as exc:
        return mark_manual_failure(
            paths,
            state,
            key,
            f"Failed to derive labels or records: {exc}",
            f"Create a valid labels.csv for {labels_path}, then rerun.",
            {"packet_fields": str(packet_fields), "labels": str(labels_path)},
            status=FAILED_STAGE,
        )

    if not records:
        return mark_manual_failure(
            paths,
            state,
            key,
            "No packet records were available for deriving inputs.",
            "Repair the parsed/normalized data and rerun.",
            {"packet_fields": str(packet_fields)},
            status=FAILED_STAGE,
        )

    try:
        _build_decision_tree_features(decision_tree_path, records, labels, dataset)
        _build_netmamba_sessions(netmamba_dir, records, labels, dataset, experiments)
    except Exception as exc:
        return mark_manual_failure(
            paths,
            state,
            key,
            f"Failed to derive model inputs: {exc}",
            "Inspect the packet schema and label mapping, then rerun.",
            {"output_root": str(output_root)},
            status=FAILED_STAGE,
        )

    manifest = output_root / "manifest.json"
    with manifest.open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "dataset": dataset["id"],
                "labels_path": str(labels_path),
                "decision_tree_features": str(decision_tree_path),
                "netmamba_dir": str(netmamba_dir),
                "record_count": len(records),
                "label_count": len(set(labels.values())),
            },
            handle,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
    state.mark_completed(
        key,
        "Derived labels, NetMamba session inputs, and Decision Tree features.",
        {
            "labels": str(labels_path),
            "decision_tree_features": str(decision_tree_path),
            "netmamba_dir": str(netmamba_dir),
            "manifest": str(manifest),
        },
    )
    return COMPLETED


def run_split(paths: ProjectPaths, state: PipelineState, dataset: dict[str, Any], experiments: dict[str, Any]) -> str:
    key = TaskKey(dataset=dataset["id"], stage="split")
    labels = paths.processed / dataset["id"] / "labels.csv"
    if not labels.exists():
        return mark_manual_failure(
            paths,
            state,
            key,
            "Cannot create train/validation/test split because labels.csv is missing.",
            f"Create {labels} according to the dataset label mapping, then rerun.",
            {"required": str(labels), "split_ratio": experiments.get("sampling", {}).get("split_ratio")},
        )
    split_file = paths.processed / dataset["id"] / "splits.json"
    if split_file.exists() and split_file.stat().st_size > 0:
        state.mark_completed(key, "Existing split file found.", {"split_file": str(split_file)})
        return COMPLETED
    try:
        split_payload = _create_split_payload(labels, experiments)
    except Exception as exc:
        return mark_manual_failure(
            paths,
            state,
            key,
            f"Automatic split generation failed: {exc}",
            f"Fix {labels} and rerun.",
            {"labels": str(labels), "target_split_file": str(split_file)},
            status=FAILED_STAGE,
        )
    with split_file.open("w", encoding="utf-8") as handle:
        json.dump(split_payload, handle, indent=2, ensure_ascii=False, sort_keys=True)
    state.mark_completed(key, "Generated train/validation/test split file.", {"split_file": str(split_file)})
    return COMPLETED


def _create_split_payload(labels_path: Path, experiments: dict[str, Any]) -> dict[str, Any]:
    with labels_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or "label" not in reader.fieldnames:
            raise ValueError("labels.csv must include a label column.")
        key_column = "session_id" if "session_id" in reader.fieldnames else "packet_index" if "packet_index" in reader.fieldnames else None
        if not key_column:
            raise ValueError("labels.csv must include session_id or packet_index.")
        rows = [(str(row[key_column]), row["label"]) for row in reader]
    if not rows:
        raise ValueError("labels.csv contains no rows.")
    by_label: dict[str, list[str]] = {}
    for item_id, label in rows:
        by_label.setdefault(label, []).append(item_id)
    split_ratio = experiments.get("sampling", {}).get("split_ratio", [0.8, 0.1, 0.1])
    payload = {"train": [], "valid": [], "test": [], "label_counts": {}}
    for label, ids in sorted(by_label.items()):
        ids = sorted(set(ids))
        n = len(ids)
        train_end = max(1, int(n * split_ratio[0]))
        valid_end = max(train_end, int(n * (split_ratio[0] + split_ratio[1])))
        if n >= 3 and valid_end == train_end:
            valid_end = train_end + 1
        payload["train"].extend({"id": item_id, "label": label} for item_id in ids[:train_end])
        payload["valid"].extend({"id": item_id, "label": label} for item_id in ids[train_end:valid_end])
        payload["test"].extend({"id": item_id, "label": label} for item_id in ids[valid_end:])
        payload["label_counts"][label] = n
    return payload


def run_mitigation_prepare(
    paths: ProjectPaths,
    state: PipelineState,
    dataset: dict[str, Any],
    strategy: str,
) -> str:
    key = TaskKey(dataset=dataset["id"], stage="mitigation_prepare", strategy=strategy)
    split_file = paths.processed / dataset["id"] / "splits.json"
    packet_fields = paths.processed / dataset["id"] / "packet_fields.jsonl"
    derived_root = paths.processed / dataset["id"] / "derived_inputs"
    if not split_file.exists() or not packet_fields.exists():
        return mark_manual_failure(
            paths,
            state,
            key,
            "Cannot prepare mitigation input because split or normalized packet fields are missing.",
            "Repair split/normalize stages and rerun.",
            {"split_file": str(split_file), "packet_fields": str(packet_fields)},
            status=FAILED_STAGE,
        )
    if not derived_root.exists():
        return mark_manual_failure(
            paths,
            state,
            key,
            "Cannot prepare mitigation input because derived model inputs are missing.",
            "Repair derive_inputs stage and rerun.",
            {"derived_root": str(derived_root)},
            status=FAILED_STAGE,
        )
    output_dir = paths.processed / dataset["id"] / "mitigation" / strategy
    output_dir.mkdir(parents=True, exist_ok=True)
    netmamba_target = output_dir / "netmamba"
    decision_tree_target = output_dir / "decision_tree_features.csv"
    source_netmamba = derived_root / "netmamba"
    source_decision_tree = derived_root / "decision_tree_features.csv"
    if source_netmamba.exists() and not netmamba_target.exists():
        shutil.copytree(source_netmamba, netmamba_target)
    if source_decision_tree.exists() and not decision_tree_target.exists():
        shutil.copyfile(source_decision_tree, decision_tree_target)
    root_decision_tree = paths.processed / dataset["id"] / "decision_tree_features.csv"
    if source_decision_tree.exists() and not root_decision_tree.exists():
        shutil.copyfile(source_decision_tree, root_decision_tree)
    output = output_dir / "manifest.json"
    with output.open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "dataset": dataset["id"],
                "strategy": strategy,
                "status": "prepared",
                "netmamba_dir": str(netmamba_target),
                "decision_tree_features": str(decision_tree_target),
                "note": "This prepares strategy-specific directories. Byte-level header rewriting must match the strategy implementation before final paper-grade runs.",
            },
            handle,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
    state.mark_completed(
        key,
        f"Prepared mitigation inputs for {strategy}.",
        {"mitigation_manifest": str(output), "netmamba_dir": str(netmamba_target), "decision_tree_features": str(decision_tree_target)},
    )
    return COMPLETED


def _load_packet_records(packet_fields: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with packet_fields.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                records.append(json.loads(line))
    return records


def _load_labels(labels_path: Path, records: list[dict[str, Any]]) -> dict[str, str]:
    if labels_path.exists():
        with labels_path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames or "label" not in reader.fieldnames:
                raise ValueError("labels.csv must include a label column.")
            key_column = "packet_index" if "packet_index" in reader.fieldnames else "session_id" if "session_id" in reader.fieldnames else None
            if not key_column:
                raise ValueError("labels.csv must include packet_index or session_id.")
            return {str(row[key_column]): row["label"] for row in reader}

    inferred = _infer_labels_from_records(records)
    if not inferred:
        raise ValueError("Could not infer labels from packet records. Create labels.csv manually.")
    labels_path.parent.mkdir(parents=True, exist_ok=True)
    with labels_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["session_id", "label", "source_file"])
        writer.writeheader()
        for session_id, label, source_file in inferred:
            writer.writerow({"session_id": session_id, "label": label, "source_file": source_file})
    return {session_id: label for session_id, label, _ in inferred}


def _infer_labels_from_records(records: list[dict[str, Any]]) -> list[tuple[str, str, str]]:
    source_labels: dict[str, set[str]] = {}
    source_session_ids: dict[str, list[str]] = {}
    for record in records:
        source_file = str(record.get("source_file", "unknown"))
        label = _guess_label(record)
        if not label:
            continue
        session_id = _guess_session_id(record)
        source_labels.setdefault(source_file, set()).add(label)
        source_session_ids.setdefault(source_file, []).append(session_id)
    inferred: list[tuple[str, str, str]] = []
    for source_file, labels in source_labels.items():
        if len(labels) != 1:
            continue
        label = next(iter(labels))
        for session_id in source_session_ids.get(source_file, []):
            inferred.append((session_id, label, source_file))
    return inferred


def _guess_label(record: dict[str, Any]) -> str | None:
    candidates = [
        record.get("frame.protocols"),
        record.get("ip.proto"),
        record.get("tls.handshake.extensions_server_name"),
        record.get("http.host"),
        record.get("tcp.stream"),
        record.get("udp.stream"),
        record.get("data.data"),
    ]
    for candidate in candidates:
        if isinstance(candidate, str) and candidate and candidate not in {"frame", "eth:ip", "eth:ip:tcp"}:
            token = re.split(r"[|/,:;\s]+", candidate)[0].strip()
            if token:
                return token
    source_file = str(record.get("source_file", ""))
    stem = Path(source_file).stem
    token = re.split(r"[_\-\s]+", stem)[0].strip()
    return token or None


def _guess_session_id(record: dict[str, Any]) -> str:
    return str(
        record.get("tcp.stream")
        or record.get("udp.stream")
        or record.get("frame.number")
        or record.get("packet_index")
        or "0"
    )


def _build_decision_tree_features(
    output_path: Path,
    records: list[dict[str, Any]],
    labels: dict[str, str],
    dataset: dict[str, Any],
) -> None:
    rows: list[dict[str, Any]] = []
    for record in records:
        session_id = _guess_session_id(record)
        label = labels.get(session_id) or labels.get(str(record.get("packet_index")))
        if not label:
            continue
        row = {
            "session_id": session_id,
            "split": "train",
            "label": label,
            "packet_index": record.get("packet_index", 0),
            "source_file": record.get("source_file", ""),
            "feature_count": len(record),
        }
        for field in ["frame.len", "ip.len", "tcp.len", "udp.length", "tcp.window_size_value", "ip.ttl"]:
            value = record.get(field)
            row[field.replace(".", "_")] = _coerce_numeric(value)
        rows.append(row)

    if not rows:
        raise ValueError("Could not derive any Decision Tree rows from records and labels.")

    split_index = max(1, int(len(rows) * 0.8))
    for index, row in enumerate(rows):
        if index >= split_index:
            row["split"] = "test"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _build_netmamba_sessions(
    output_dir: Path,
    records: list[dict[str, Any]],
    labels: dict[str, str],
    dataset: dict[str, Any],
    experiments: dict[str, Any],
) -> None:
    session_root = output_dir
    session_root.mkdir(parents=True, exist_ok=True)
    bucketed: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        session_id = _guess_session_id(record)
        label = labels.get(session_id) or labels.get(str(record.get("packet_index")))
        if not label:
            continue
        bucketed.setdefault(label, []).append(record)

    if not bucketed:
        raise ValueError("Could not derive any NetMamba session buckets from records and labels.")

    split_names = ["train", "valid", "test"]
    for split_name in split_names:
        (session_root / split_name).mkdir(parents=True, exist_ok=True)
    for label, bucket in bucketed.items():
        bucket = bucket[: experiments.get("sampling", {}).get("max_flows_per_class", 500)]
        train_end = max(1, int(len(bucket) * 0.8))
        valid_end = max(train_end + 1, int(len(bucket) * 0.9)) if len(bucket) > 2 else len(bucket)
        partitions = {
            "train": bucket[:train_end],
            "valid": bucket[train_end:valid_end],
            "test": bucket[valid_end:],
        }
        for split_name, items in partitions.items():
            class_dir = session_root / split_name / _sanitize_name(label)
            class_dir.mkdir(parents=True, exist_ok=True)
            for index, item in enumerate(items):
                image_path = class_dir / f"{Path(str(item.get('source_file', 'sample'))).stem}_{index:06d}.png"
                _write_netmamba_png(item, image_path)


def _write_netmamba_png(record: dict[str, Any], image_path: Path) -> None:
    try:
        from PIL import Image
    except ImportError as exc:
        raise RuntimeError("Pillow is required to write NetMamba 40x40 PNG inputs.") from exc

    payload = _record_to_1600_bytes(record)
    image = Image.frombytes("L", (40, 40), payload)
    image.save(image_path)


def _record_to_1600_bytes(record: dict[str, Any]) -> bytes:
    raw = _extract_raw_packet_bytes(record)
    if not raw:
        digest = hashlib.sha256(json.dumps(record, sort_keys=True, ensure_ascii=False).encode("utf-8")).digest()
        raw = (digest * ((1600 // len(digest)) + 1))[:1600]
    if len(raw) < 1600:
        raw = raw + bytes(1600 - len(raw))
    return raw[:1600]


def _extract_raw_packet_bytes(record: dict[str, Any]) -> bytes:
    preferred_keys = ["frame_raw", "data.data", "tcp.payload", "udp.payload"]
    for key in preferred_keys:
        value = record.get(key)
        raw = _parse_hex_bytes(value)
        if raw:
            return raw
    for key, value in record.items():
        if key.endswith("_raw") or key.endswith(".raw"):
            raw = _parse_hex_bytes(value)
            if raw:
                return raw
    return b""


def _parse_hex_bytes(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        return b""
    compact = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(compact) < 2:
        return b""
    if len(compact) % 2:
        compact = compact[:-1]
    try:
        return bytes.fromhex(compact)
    except ValueError:
        return b""


def _coerce_numeric(value: Any) -> float | int | str:
    if value is None:
        return 0
    if isinstance(value, (int, float)):
        return value
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0


def _sanitize_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name)


def run_train_eval(
    paths: ProjectPaths,
    state: PipelineState,
    dataset: dict[str, Any],
    experiments: dict[str, Any],
    model: str,
    strategy: str,
) -> str:
    key = TaskKey(dataset=dataset["id"], stage="train_eval", model=model, strategy=strategy)
    mitigation_manifest = paths.processed / dataset["id"] / "mitigation" / strategy / "manifest.json"
    if not mitigation_manifest.exists():
        return mark_manual_failure(
            paths,
            state,
            key,
            "Cannot train/evaluate because mitigation input is missing.",
            "Repair mitigation_prepare stage and rerun.",
            {"required": str(mitigation_manifest)},
            status=FAILED_STAGE,
        )

    model_config = experiments.get("models", {}).get(model, {})
    if model == "netmamba":
        command = model_config.get("train_command")
        if not command:
            return mark_manual_failure(
                paths,
                state,
                key,
                "NetMamba train/eval command is not configured.",
                "Add the official NetMamba command/checkpoint path to configs/experiments.json, then rerun.",
                {"config_path": "configs/experiments.json", "model": model, "strategy": strategy},
                status=FAILED_STAGE,
            )
        return _run_external_train_command(paths, state, key, command, dataset, strategy, model_config)

    if model == "decision_tree":
        features = paths.processed / dataset["id"] / "mitigation" / strategy / "decision_tree_features.csv"
        if not features.exists():
            features = paths.processed / dataset["id"] / "decision_tree_features.csv"
        if not features.exists():
            return mark_manual_failure(
                paths,
                state,
                key,
                "Decision Tree feature matrix is missing.",
                f"Create {features} from the same mitigation input and split, then rerun.",
                {"required": str(features)},
                status=FAILED_STAGE,
            )
        return _run_builtin_decision_tree(paths, state, key, features, dataset, strategy)

    return mark_manual_failure(
        paths,
        state,
        key,
        f"Unknown model: {model}",
        "Fix configs/experiments.json and rerun.",
        {"model": model},
        status=FAILED_STAGE,
    )


def _run_external_train_command(
    paths: ProjectPaths,
    state: PipelineState,
    key: TaskKey,
    command: str,
    dataset: dict[str, Any],
    strategy: str,
    model_config: dict[str, Any],
) -> str:
    log_path = paths.logs / f"{dataset['id']}_{key.model}_{strategy}.log"
    data_path = paths.processed / dataset["id"] / "mitigation" / strategy / "netmamba"
    output_dir = paths.outputs / "checkpoints" / dataset["id"] / strategy / str(key.model)
    output_dir.mkdir(parents=True, exist_ok=True)
    checkpoint_path = paths.root / model_config.get("checkpoint_path", "")
    nb_classes = dataset.get("mitigation", {}).get("used_classes") or dataset.get("mitigation", {}).get("paper_classes") or ""
    env_command = command.format(
        dataset=dataset["id"],
        strategy=strategy,
        data_path=str(data_path),
        output_dir=str(output_dir),
        checkpoint_path=str(checkpoint_path),
        nb_classes=nb_classes,
        project_root=str(paths.root),
    )
    with log_path.open("w", encoding="utf-8") as handle:
        result = subprocess.run(env_command, shell=True, stdout=handle, stderr=subprocess.STDOUT, text=True)
    if result.returncode != 0:
        return mark_manual_failure(
            paths,
            state,
            key,
            f"External train/eval command failed with exit code {result.returncode}.",
            "Inspect the log, fix the model command/checkpoint/data issue, then rerun.",
            {"command": env_command, "log": str(log_path)},
            status=FAILED_STAGE,
        )
    metrics_path = paths.tables / dataset["id"] / f"{strategy}_{key.model}_metrics.json"
    official_metrics = output_dir / "metrics.json"
    if official_metrics.exists():
        metrics_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(official_metrics, metrics_path)
    if not metrics_path.exists():
        return mark_manual_failure(
            paths,
            state,
            key,
            "External train/eval command completed but did not produce the required metrics JSON.",
            f"Write metrics to {metrics_path} with an accuracy field, then rerun report generation or the stage.",
            {"command": env_command, "log": str(log_path), "required_metrics": str(metrics_path)},
            status=FAILED_STAGE,
        )
    state.mark_completed(key, "External train/eval command completed.", {"log": str(log_path), "metrics": str(metrics_path)})
    return COMPLETED


def _run_builtin_decision_tree(
    paths: ProjectPaths,
    state: PipelineState,
    key: TaskKey,
    features: Path,
    dataset: dict[str, Any],
    strategy: str,
) -> str:
    try:
        from .models.decision_tree import train_decision_tree

        result = train_decision_tree(features)
    except Exception as exc:  # pragma: no cover - dependency/data dependent
        return mark_manual_failure(
            paths,
            state,
            key,
            f"Decision Tree training failed: {exc}",
            "Inspect the feature matrix schema and install scikit-learn if needed, then rerun.",
            {"features": str(features)},
            status=FAILED_STAGE,
        )

    out_dir = paths.tables / dataset["id"]
    out_dir.mkdir(parents=True, exist_ok=True)
    output = out_dir / f"{strategy}_decision_tree_metrics.json"
    with output.open("w", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2, ensure_ascii=False, sort_keys=True)
    state.mark_completed(key, "Decision Tree evaluation completed.", {"metrics": str(output), "accuracy": result.get("accuracy")})
    return COMPLETED


STAGE_RUNNERS = {
    "download": run_download,
    "verify_data": run_verify_data,
    "parse": run_parse,
    "normalize": run_normalize,
    "ami_detection": run_ami_detection,
}


def run_netmamba_pretrain_prepare(paths: ProjectPaths, state: PipelineState, experiments: dict[str, Any]) -> str:
    key = TaskKey(dataset="__global__", stage="netmamba_pretrain_prepare")
    pretrain_datasets = experiments.get("netmamba_pretrain_datasets", [])
    target_root = paths.root / "data/processed/netmamba_pretrain/bidirectional_sessions"
    try:
        copied = _merge_netmamba_pretrain_inputs(paths, pretrain_datasets, target_root)
    except Exception as exc:
        return mark_manual_failure(
            paths,
            state,
            key,
            f"Failed to prepare NetMamba pre-training inputs: {exc}",
            "Repair each pre-training dataset's derive_inputs output and rerun.",
            {"pretrain_datasets": pretrain_datasets, "target_root": str(target_root)},
            status=FAILED_STAGE,
        )
    manifest = target_root / "manifest.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with manifest.open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "pretrain_datasets": pretrain_datasets,
                "target_root": str(target_root),
                "copied_files": copied,
                "flow_direction": experiments.get("netmamba_input", {}).get("flow_direction"),
                "header_policy": experiments.get("netmamba_input", {}).get("header_policy"),
            },
            handle,
            indent=2,
            ensure_ascii=False,
            sort_keys=True,
        )
    state.mark_completed(
        key,
        "Prepared merged NetMamba bidirectional-session pre-training inputs.",
        {"target_root": str(target_root), "manifest": str(manifest), "copied_files": copied},
    )
    return COMPLETED


def _merge_netmamba_pretrain_inputs(paths: ProjectPaths, dataset_ids: list[str], target_root: Path) -> int:
    copied = 0
    for dataset_id in dataset_ids:
        source_root = paths.processed / dataset_id / "derived_inputs" / "netmamba"
        if not source_root.exists():
            raise FileNotFoundError(f"Missing derived NetMamba input for {dataset_id}: {source_root}")
        for split_dir in source_root.iterdir():
            if not split_dir.is_dir():
                continue
            for class_dir in split_dir.iterdir():
                if not class_dir.is_dir():
                    continue
                target_class_dir = target_root / split_dir.name / f"{dataset_id}__{class_dir.name}"
                target_class_dir.mkdir(parents=True, exist_ok=True)
                for item in class_dir.iterdir():
                    if item.is_file():
                        target = target_class_dir / item.name
                        if not target.exists():
                            shutil.copyfile(item, target)
                        copied += 1
    if copied == 0:
        raise ValueError("No NetMamba pre-training files were copied.")
    return copied


def run_netmamba_pretrain(paths: ProjectPaths, state: PipelineState, experiments: dict[str, Any]) -> str:
    key = TaskKey(dataset="__global__", stage="netmamba_pretrain")
    model_config = experiments.get("models", {}).get("netmamba", {})
    command = model_config.get("pretrain_command")
    if not command:
        return mark_manual_failure(
            paths,
            state,
            key,
            "NetMamba reproduction pre-training command is not configured.",
            "Configure models.netmamba.pretrain_command in configs/experiments.json and rerun.",
            {"config_path": "configs/experiments.json"},
            status=FAILED_STAGE,
        )

    required_data = paths.root / "data/processed/netmamba_pretrain/bidirectional_sessions"
    if not required_data.exists():
        return mark_manual_failure(
            paths,
            state,
            key,
            "NetMamba pre-training data is missing.",
            "Build NetMamba pre-training inputs from bidirectional session flows for the six paper datasets, then rerun.",
            {
                "required_data": str(required_data),
                "pretrain_datasets": experiments.get("netmamba_pretrain_datasets", []),
                "flow_direction": experiments.get("netmamba_input", {}).get("flow_direction"),
                "header_policy": experiments.get("netmamba_input", {}).get("header_policy"),
            },
            status=FAILED_STAGE,
        )

    log_path = paths.logs / "netmamba_reproduced_pretrain.log"
    output_dir = paths.root / "outputs/checkpoints/netmamba_reproduced_pretrain"
    output_dir.mkdir(parents=True, exist_ok=True)
    env_command = command.format(project_root=str(paths.root), output_dir=str(output_dir), data_path=str(required_data))
    with log_path.open("w", encoding="utf-8") as handle:
        result = subprocess.run(env_command, shell=True, stdout=handle, stderr=subprocess.STDOUT, text=True)
    if result.returncode != 0:
        return mark_manual_failure(
            paths,
            state,
            key,
            f"NetMamba reproduction pre-training failed with exit code {result.returncode}.",
            "Inspect the pre-training log, fix data/environment issues, then rerun.",
            {"command": env_command, "log": str(log_path)},
            status=FAILED_STAGE,
        )
    checkpoint = paths.root / model_config.get("checkpoint_path", "")
    if not checkpoint.exists():
        return mark_manual_failure(
            paths,
            state,
            key,
            "NetMamba reproduction pre-training completed but did not produce the required checkpoint.",
            f"Save the reproduced pre-training checkpoint to {checkpoint}, then rerun.",
            {"required_checkpoint": str(checkpoint), "log": str(log_path)},
            status=FAILED_STAGE,
        )
    state.mark_completed(
        key,
        "Reproduced NetMamba pre-training checkpoint is available.",
        {"checkpoint": str(checkpoint), "log": str(log_path)},
    )
    return COMPLETED
