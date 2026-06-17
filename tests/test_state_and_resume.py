from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from biasseeker.download import run_download
from biasseeker.paths import ProjectPaths
from biasseeker.scheduler import initialize_state, run_pipeline, summarize_tasks
from biasseeker.state import AWAITING_MANUAL_FIX, COMPLETED, PipelineState


class ResumePipelineTests(unittest.TestCase):
    def make_paths(self) -> ProjectPaths:
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        paths = ProjectPaths(Path(temp.name))
        paths.ensure()
        return paths

    def test_download_waits_for_manual_file_then_recovers(self) -> None:
        paths = self.make_paths()
        state = PipelineState.load(paths.state_file)
        dataset = {
            "id": "sample",
            "name": "Sample",
            "download_url": None,
            "manual_source": "manual fixture",
            "expected_files": ["sample.pcap"],
            "checksum": None,
        }

        first = run_download(paths, state, dataset)
        self.assertEqual(first, AWAITING_MANUAL_FIX)
        self.assertTrue((paths.failures / "sample" / "download" / "failure_report.md").exists())

        raw_dir = paths.raw / "sample"
        raw_dir.mkdir(parents=True, exist_ok=True)
        (raw_dir / "sample.pcap").write_bytes(b"pcap bytes")

        second = run_download(paths, state, dataset)
        self.assertEqual(second, COMPLETED)
        task = PipelineState.load(paths.state_file).data["tasks"]["sample::download"]
        self.assertEqual(task["status"], COMPLETED)

    def test_pipeline_does_not_skip_unrelated_dataset_when_one_download_fails(self) -> None:
        paths = self.make_paths()
        state = PipelineState.load(paths.state_file)
        datasets = [
            {
                "id": "missing",
                "name": "Missing",
                "task": "vpn",
                "download_url": None,
                "manual_source": "manual",
                "expected_files": ["missing.pcap"],
                "checksum": None,
            },
            {
                "id": "present",
                "name": "Present",
                "task": "vpn",
                "download_url": None,
                "manual_source": "manual",
                "expected_files": ["present.pcap"],
                "checksum": None,
            },
        ]
        experiments = {"stages": ["download"], "models": {}, "mitigation_strategies": []}
        present_dir = paths.raw / "present"
        present_dir.mkdir(parents=True, exist_ok=True)
        (present_dir / "present.pcap").write_bytes(b"pcap bytes")

        run_pipeline(paths, state, datasets, experiments)
        reloaded = PipelineState.load(paths.state_file)
        self.assertEqual(reloaded.data["tasks"]["missing::download"]["status"], AWAITING_MANUAL_FIX)
        self.assertEqual(reloaded.data["tasks"]["present::download"]["status"], COMPLETED)

    def test_initialize_state_is_idempotent(self) -> None:
        paths = self.make_paths()
        state = PipelineState.load(paths.state_file)
        datasets = [{"id": "sample", "name": "Sample", "task": "vpn"}]
        experiments = {"stages": ["download", "verify_data"], "models": {}, "mitigation_strategies": []}
        initialize_state(state, datasets, experiments)
        initialize_state(state, datasets, experiments)
        summary = summarize_tasks(PipelineState.load(paths.state_file).tasks())
        self.assertEqual(summary["ready"], 3)

    def test_download_archive_is_unpacked_before_expected_file_check(self) -> None:
        paths = self.make_paths()
        state = PipelineState.load(paths.state_file)
        archive_source = paths.root / "source_archive"
        archive_source.mkdir()
        (archive_source / "inside.pcap").write_bytes(b"pcap bytes")
        archive_base = paths.root / "fixture"
        archive_path = shutil.make_archive(str(archive_base), "zip", archive_source)
        dataset = {
            "id": "archive_sample",
            "name": "Archive Sample",
            "download_url": Path(archive_path).as_uri(),
            "manual_source": "fixture",
            "expected_files": ["inside.pcap"],
            "checksum": None,
        }

        result = run_download(paths, state, dataset)
        self.assertEqual(result, COMPLETED)
        self.assertTrue((paths.raw / "archive_sample" / "inside.pcap").exists())


if __name__ == "__main__":
    unittest.main()
