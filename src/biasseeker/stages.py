from __future__ import annotations

import csv
import json
import shutil
import subprocess
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
        command = ["tshark", "-r", str(capture), "-T", "json"]
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
    return mark_manual_failure(
        paths,
        state,
        key,
        "Automatic split generation is blocked until label schema is confirmed.",
        f"Create {split_file} or update the label schema adapter, then rerun.",
        {"labels": str(labels), "target_split_file": str(split_file)},
        status=FAILED_STAGE,
    )


def run_mitigation_prepare(
    paths: ProjectPaths,
    state: PipelineState,
    dataset: dict[str, Any],
    strategy: str,
) -> str:
    key = TaskKey(dataset=dataset["id"], stage="mitigation_prepare", strategy=strategy)
    split_file = paths.processed / dataset["id"] / "splits.json"
    packet_fields = paths.processed / dataset["id"] / "packet_fields.jsonl"
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
    output = paths.processed / dataset["id"] / "mitigation" / strategy / "manifest.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    if not output.exists():
        with output.open("w", encoding="utf-8") as handle:
            json.dump(
                {
                    "dataset": dataset["id"],
                    "strategy": strategy,
                    "status": "prepared_placeholder",
                    "note": "Implement field-level byte rewriting here before running full experiments.",
                },
                handle,
                indent=2,
                ensure_ascii=False,
            )
    state.mark_completed(key, f"Prepared mitigation manifest for {strategy}.", {"mitigation_manifest": str(output)})
    return COMPLETED


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
