from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from biasseeker.stages import _write_netmamba_png


class NetMambaPngTests(unittest.TestCase):
    def test_write_netmamba_png_is_40_by_40(self) -> None:
        try:
            from PIL import Image
        except ImportError:
            self.skipTest("Pillow is not installed")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sample.png"
            _write_netmamba_png({"frame_raw": "00:01:02:03"}, path)
            with Image.open(path) as image:
                self.assertEqual(image.size, (40, 40))
                self.assertEqual(image.mode, "L")


if __name__ == "__main__":
    unittest.main()
