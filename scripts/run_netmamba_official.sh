#!/usr/bin/env bash
set -euo pipefail

REPO=""
DATASET=""
STRATEGY=""
DATA_PATH=""
OUTPUT_DIR=""
CHECKPOINT=""
NB_CLASSES=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --dataset) DATASET="$2"; shift 2 ;;
    --strategy) STRATEGY="$2"; shift 2 ;;
    --data-path) DATA_PATH="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    --checkpoint) CHECKPOINT="$2"; shift 2 ;;
    --nb-classes) NB_CLASSES="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "${REPO}" || ! -d "${REPO}" ]]; then
  echo "NetMamba official repository is missing. Run: bash scripts/setup_netmamba_official.sh" >&2
  exit 10
fi

if [[ -z "${CHECKPOINT}" || ! -s "${CHECKPOINT}" ]]; then
  echo "NetMamba checkpoint is missing at ${CHECKPOINT}. Run: bash scripts/setup_netmamba_official.sh" >&2
  exit 11
fi

if [[ -z "${DATA_PATH}" || ! -d "${DATA_PATH}" ]]; then
  echo "NetMamba data path is missing: ${DATA_PATH}" >&2
  echo "Prepare mitigation data in the official train/valid/test class-folder layout before rerunning." >&2
  exit 12
fi

if [[ -z "${NB_CLASSES}" ]]; then
  echo "Number of classes is not configured for dataset ${DATASET}." >&2
  exit 13
fi

mkdir -p "${OUTPUT_DIR}"

CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-0}" python "${REPO}/src/fine-tune.py" \
  --blr 2e-3 \
  --epochs 120 \
  --nb_classes "${NB_CLASSES}" \
  --finetune "${CHECKPOINT}" \
  --data_path "${DATA_PATH}" \
  --output_dir "${OUTPUT_DIR}" \
  --log_dir "${OUTPUT_DIR}" \
  --model net_mamba_classifier \
  --no_amp

python - <<PY
import json
from pathlib import Path

output_dir = Path("${OUTPUT_DIR}")
metrics_path = output_dir / "metrics.json"
if not metrics_path.exists():
    candidates = list(output_dir.glob("*.json")) + list(output_dir.glob("*.txt")) + list(output_dir.glob("*.log"))
    raise SystemExit(
        "Official fine-tune command completed, but no metrics.json was found. "
        f"Inspect {output_dir} and convert the official evaluation output into metrics.json. "
        f"Candidate logs: {[str(p) for p in candidates]}"
    )

payload = json.loads(metrics_path.read_text(encoding="utf-8"))
if "accuracy" not in payload:
    raise SystemExit(f"{metrics_path} must contain an accuracy field.")
PY
