from __future__ import annotations

from pathlib import Path


class ProjectPaths:
    def __init__(self, root: Path | str = ".") -> None:
        self.root = Path(root).resolve()
        self.data = self.root / "data"
        self.raw = self.data / "raw"
        self.interim = self.data / "interim"
        self.processed = self.data / "processed"
        self.outputs = self.root / "outputs"
        self.state_dir = self.outputs / "state"
        self.failures = self.outputs / "failures"
        self.tables = self.outputs / "tables"
        self.figures = self.outputs / "figures"
        self.logs = self.outputs / "logs"
        self.reports = self.root / "reports"

    def ensure(self) -> None:
        for path in [
            self.raw,
            self.interim,
            self.processed,
            self.state_dir,
            self.failures,
            self.tables,
            self.figures,
            self.logs,
            self.reports,
        ]:
            path.mkdir(parents=True, exist_ok=True)

    @property
    def state_file(self) -> Path:
        return self.state_dir / "pipeline_state.json"
