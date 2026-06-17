from __future__ import annotations

import hashlib
import shutil
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .failures import write_failure
from .paths import ProjectPaths
from .state import AWAITING_MANUAL_FIX, DOWNLOAD_FAILED, COMPLETED, PipelineState, TaskKey


def dataset_raw_dir(paths: ProjectPaths, dataset: dict[str, Any]) -> Path:
    return paths.raw / dataset["id"]


def expected_paths(paths: ProjectPaths, dataset: dict[str, Any]) -> list[Path]:
    return [dataset_raw_dir(paths, dataset) / item for item in dataset.get("expected_files", [])]


def has_expected_files(paths: ProjectPaths, dataset: dict[str, Any]) -> bool:
    expected = expected_paths(paths, dataset)
    if expected:
        return all(path.exists() and path.stat().st_size > 0 for path in expected)
    raw_dir = dataset_raw_dir(paths, dataset)
    return raw_dir.exists() and any(path.is_file() and path.stat().st_size > 0 for path in raw_dir.rglob("*"))


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_checksum(paths: ProjectPaths, dataset: dict[str, Any]) -> tuple[bool, str]:
    checksum = dataset.get("checksum")
    if not checksum:
        return True, "No checksum configured."
    expected = expected_paths(paths, dataset)
    if len(expected) != 1:
        return False, "Checksum validation currently expects exactly one expected file."
    actual = file_sha256(expected[0])
    if actual.lower() == checksum.lower():
        return True, "Checksum matched."
    return False, f"Checksum mismatch: expected {checksum}, got {actual}."


def run_download(paths: ProjectPaths, state: PipelineState, dataset: dict[str, Any]) -> str:
    key = TaskKey(dataset=dataset["id"], stage="download")
    raw_dir = dataset_raw_dir(paths, dataset)
    raw_dir.mkdir(parents=True, exist_ok=True)

    if has_expected_files(paths, dataset):
        ok, message = verify_checksum(paths, dataset)
        if ok:
            state.mark_completed(key, f"Dataset files are present. {message}")
            return COMPLETED
        report, manifest = write_failure(
            paths.failures,
            key,
            message,
            f"Replace the corrupted files under {raw_dir} and rerun python -m biasseeker.cli run.",
            {"raw_dir": str(raw_dir), "expected_files": dataset.get("expected_files", [])},
        )
        state.mark_failed(key, AWAITING_MANUAL_FIX, message, str(manifest), {"failure_report": str(report)})
        return AWAITING_MANUAL_FIX

    url = dataset.get("download_url")
    if not url:
        expected = ", ".join(dataset.get("expected_files", [])) or "dataset files"
        message = "No automatic download URL is configured for this dataset."
        action = (
            f"Download {dataset['name']} manually from {dataset.get('manual_source', 'the paper source')} "
            f"and place {expected} under {raw_dir}."
        )
        report, manifest = write_failure(
            paths.failures,
            key,
            message,
            action,
            {
                "raw_dir": str(raw_dir),
                "expected_files": dataset.get("expected_files", []),
                "manual_source": dataset.get("manual_source", ""),
            },
        )
        state.mark_failed(key, AWAITING_MANUAL_FIX, message, str(manifest), {"failure_report": str(report)})
        return AWAITING_MANUAL_FIX

    target_name = _download_filename(url, dataset)
    target_path = raw_dir / target_name
    try:
        urllib.request.urlretrieve(url, target_path)
    except (urllib.error.URLError, OSError) as exc:
        message = f"Automatic download failed: {exc}"
        action = f"Download the dataset manually and place files under {raw_dir}, then rerun the pipeline."
        report, manifest = write_failure(
            paths.failures,
            key,
            message,
            action,
            {"url": url, "target_path": str(target_path)},
        )
        state.mark_failed(key, DOWNLOAD_FAILED, message, str(manifest), {"failure_report": str(report)})
        return DOWNLOAD_FAILED

    if _looks_like_archive(target_path):
        try:
            shutil.unpack_archive(str(target_path), str(raw_dir))
        except (shutil.ReadError, OSError) as exc:
            message = f"Downloaded file could not be unpacked: {exc}"
            report, manifest = write_failure(
                paths.failures,
                key,
                message,
                f"Manually extract {target_path} under {raw_dir}, then rerun the pipeline.",
                {"archive": str(target_path), "raw_dir": str(raw_dir)},
            )
            state.mark_failed(key, AWAITING_MANUAL_FIX, message, str(manifest), {"failure_report": str(report)})
            return AWAITING_MANUAL_FIX

    ok, message = verify_checksum(paths, dataset)
    if not ok:
        report, manifest = write_failure(
            paths.failures,
            key,
            message,
            f"Replace {target_path} with a valid copy and rerun the pipeline.",
            {"target_path": str(target_path)},
        )
        state.mark_failed(key, AWAITING_MANUAL_FIX, message, str(manifest), {"failure_report": str(report)})
        return AWAITING_MANUAL_FIX

    state.mark_completed(key, f"Downloaded dataset from {url}. {message}", {"downloaded_file": str(target_path)})
    return COMPLETED


def _download_filename(url: str, dataset: dict[str, Any]) -> str:
    parsed = urllib.parse.urlparse(url)
    url_name = Path(parsed.path).name
    if url_name:
        return url_name
    expected = dataset.get("expected_files", [])
    if expected:
        return expected[0]
    return f"{dataset['id']}.download"


def _looks_like_archive(path: Path) -> bool:
    suffixes = "".join(path.suffixes).lower()
    return suffixes.endswith((".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz"))
