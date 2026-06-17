#!/usr/bin/env bash
set -euo pipefail

REPO=""
DATA_PATH=""
OUTPUT_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --data-path) DATA_PATH="$2"; shift 2 ;;
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "${REPO}" || ! -d "${REPO}" ]]; then
  echo "NetMamba official repository is missing. Run: bash scripts/setup_netmamba_official.sh" >&2
  exit 10
fi

if [[ -z "${DATA_PATH}" || ! -d "${DATA_PATH}" ]]; then
  echo "NetMamba reproduction pre-training data is missing: ${DATA_PATH}" >&2
  echo "Build it from bidirectional session flows for CICIOT2022, CrossPlatform Android/iOS, ISCXVPN2016, USTC-TFC2016, and ISCXTor2016." >&2
  exit 12
fi

mkdir -p "${OUTPUT_DIR}"

if [[ -f "${REPO}/src/pre-train.py" ]]; then
  CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-0}" python "${REPO}/src/pre-train.py" \
    --data_path "${DATA_PATH}" \
    --output_dir "${OUTPUT_DIR}" \
    --log_dir "${OUTPUT_DIR}" \
    --model net_mamba
elif [[ -f "${REPO}/src/main_pretrain.py" ]]; then
  CUDA_VISIBLE_DEVICES="${CUDA_VISIBLE_DEVICES:-0}" python "${REPO}/src/main_pretrain.py" \
    --data_path "${DATA_PATH}" \
    --output_dir "${OUTPUT_DIR}" \
    --log_dir "${OUTPUT_DIR}" \
    --model net_mamba
else
  echo "Could not find official NetMamba pre-training entrypoint under ${REPO}/src." >&2
  echo "Inspect the official repository and update scripts/pretrain_netmamba_reproduction.sh." >&2
  exit 20
fi

if [[ ! -s "${OUTPUT_DIR}/pre-train.pth" ]]; then
  latest_ckpt="$(find "${OUTPUT_DIR}" -type f \( -name '*.pth' -o -name '*.pt' \) | sort | tail -n 1 || true)"
  if [[ -n "${latest_ckpt}" ]]; then
    cp "${latest_ckpt}" "${OUTPUT_DIR}/pre-train.pth"
  fi
fi

if [[ ! -s "${OUTPUT_DIR}/pre-train.pth" ]]; then
  echo "Pre-training finished but ${OUTPUT_DIR}/pre-train.pth was not found." >&2
  exit 21
fi
