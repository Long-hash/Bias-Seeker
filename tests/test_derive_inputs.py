from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from biasseeker.paths import ProjectPaths
from biasseeker.stages import run_derive_inputs
from biasseeker.state import COMPLETED, PipelineState


class DeriveInputsTests(unittest.TestCase):
    def test_derive_inputs_creates_labels_netmamba_and_decision_tree_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            paths = ProjectPaths(Path(tmp))
            paths.ensure()
            dataset = {"id": "sample", "name": "Sample"}
            processed = paths.processed / "sample"
            processed.mkdir(parents=True)
            packet_fields = processed / "packet_fields.jsonl"
            records = [
                {
                    "dataset": "sample",
                    "source_file": "classA_capture.json",
                    "packet_index": 0,
                    "tcp.stream": "0",
                    "frame.len": "100",
                    "ip.ttl": "64",
                },
                {
                    "dataset": "sample",
                    "source_file": "classA_capture.json",
                    "packet_index": 1,
                    "tcp.stream": "0",
                    "frame.len": "120",
                    "ip.ttl": "64",
                },
            ]
            packet_fields.write_text("\n".join(json.dumps(row) for row in records) + "\n", encoding="utf-8")
            state = PipelineState.load(paths.state_file)
            experiments = {"sampling": {"max_flows_per_class": 500}}

            result = run_derive_inputs(paths, state, dataset, experiments)

            self.assertEqual(result, COMPLETED)
            self.assertTrue((processed / "labels.csv").exists())
            self.assertTrue((processed / "derived_inputs" / "decision_tree_features.csv").exists())
            self.assertTrue((processed / "derived_inputs" / "netmamba" / "train").exists())


if __name__ == "__main__":
    unittest.main()
