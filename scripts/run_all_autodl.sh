#!/usr/bin/env bash
set -euo pipefail

python -m biasseeker.cli init
python -m biasseeker.cli run
python -m biasseeker.cli report
