from __future__ import annotations

import argparse
import json
from pathlib import Path

from .config import load_configs
from .paths import ProjectPaths
from .report import generate_reports
from .scheduler import initialize_state, run_pipeline, summarize_tasks
from .state import PipelineState


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the resumable BiasSeeker reproduction pipeline.")
    parser.add_argument("--root", default=".", help="Project root. Defaults to current directory.")
    parser.add_argument("--datasets", default="configs/datasets.json", help="Datasets config path.")
    parser.add_argument("--experiments", default="configs/experiments.json", help="Experiments config path.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("init", help="Initialize state files and directories.")
    subparsers.add_parser("run", help="Run or resume the pipeline.")
    subparsers.add_parser("status", help="Print task status summary.")
    subparsers.add_parser("report", help="Generate Markdown reports from current state.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = Path(args.root)
    paths = ProjectPaths(root)
    paths.ensure()
    datasets_config, experiments = load_configs(root / args.datasets, root / args.experiments)
    state = PipelineState.load(paths.state_file)

    if args.command == "init":
        initialize_state(state, datasets_config.get("datasets", []), experiments)
        print(f"Initialized state at {paths.state_file}")
        return 0

    if args.command == "run":
        run_pipeline(paths, state, datasets_config.get("datasets", []), experiments)
        generate_reports(paths, state, datasets_config, experiments)
        print(json.dumps(summarize_tasks(state.tasks()), indent=2, ensure_ascii=False, sort_keys=True))
        return 0

    if args.command == "status":
        initialize_state(state, datasets_config.get("datasets", []), experiments)
        print(json.dumps(summarize_tasks(state.tasks()), indent=2, ensure_ascii=False, sort_keys=True))
        return 0

    if args.command == "report":
        initialize_state(state, datasets_config.get("datasets", []), experiments)
        main_report, app_report = generate_reports(paths, state, datasets_config, experiments)
        print(f"Wrote {main_report}")
        print(f"Wrote {app_report}")
        return 0

    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
