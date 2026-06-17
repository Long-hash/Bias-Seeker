#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="${1:-external/NetMamba}"
REPO_URL="https://github.com/wangtz19/NetMamba.git"
CHECKPOINT_URL="https://huggingface.co/wangtz/NetMamba/resolve/main/pre-train.pth"
CHECKPOINT_DIR="${REPO_DIR}/checkpoints"
CHECKPOINT_PATH="${CHECKPOINT_DIR}/pre-train.pth"

mkdir -p "$(dirname "${REPO_DIR}")"

if [[ ! -d "${REPO_DIR}/.git" ]]; then
  git clone "${REPO_URL}" "${REPO_DIR}"
else
  git -C "${REPO_DIR}" fetch --all --tags
fi

python -m pip install torch==2.1.1 torchvision==0.16.1 --index-url https://download.pytorch.org/whl/cu121

pushd "${REPO_DIR}/mamba-1p1p1" >/dev/null
python -m pip install -e .
popd >/dev/null

python -m pip install -r "${REPO_DIR}/requirements.txt"

mkdir -p "${CHECKPOINT_DIR}"
if [[ ! -s "${CHECKPOINT_PATH}" ]]; then
  if command -v wget >/dev/null 2>&1; then
    wget -O "${CHECKPOINT_PATH}" "${CHECKPOINT_URL}"
  else
    python - <<PY
from urllib.request import urlretrieve
urlretrieve("${CHECKPOINT_URL}", "${CHECKPOINT_PATH}")
PY
  fi
fi

echo "NetMamba repo: ${REPO_DIR}"
echo "NetMamba checkpoint: ${CHECKPOINT_PATH}"
