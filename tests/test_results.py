from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from biasseeker.paths import ProjectPaths
from biasseeker.results import generate_result_tables


class ResultTableTests(unittest.TestCase):
    def test_result_tables_include_pending_and_completed_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = ProjectPaths(Path(tmp))
            paths.ensure()
            metrics_dir = paths.tables / "crossnet2021"
            metrics_dir.mkdir(parents=True)
            (metrics_dir / "none_full_feature_decision_tree_metrics.json").write_text(
                json.dumps({"accuracy": 0.75}),
                encoding="utf-8",
            )
            datasets = [
                {
                    "id": "crossnet2021",
                    "name": "CrossNet2021",
                    "task": "encrypted_application",
                    "application_focus": True,
                    "mitigation": {"used_classes": 20},
                }
            ]
            experiments = {
                "mitigation_strategies": ["none_full_feature"],
                "models": {
                    "netmamba": {"enabled": True},
                    "decision_tree": {"enabled": True},
                },
            }

            generated = generate_result_tables(paths, datasets, experiments)
            combined = Path(generated["combined"]).read_text(encoding="utf-8")
            self.assertIn("decision_tree,completed,0.75", combined)
            self.assertIn("netmamba,pending,", combined)


if __name__ == "__main__":
    unittest.main()
