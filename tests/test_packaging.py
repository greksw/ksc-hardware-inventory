import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile
from tools.build_ksc_collector import build


class PackagingTests(unittest.TestCase):
    def test_zip_uses_posix_paths(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cmd = root / "Run-RamInventory.cmd"
            ps1 = root / "Collect-RamInventory.ps1"
            cmd.write_text("@echo off\r\n")
            ps1.write_text("Write-Output 'TEST'\n")
            output = root / "bundle.zip"
            build(cmd, ps1, output)
            with ZipFile(output) as z:
                self.assertEqual(set(z.namelist()), {
                    "utility/Run-RamInventory.cmd", "utility/Collect-RamInventory.ps1"})
