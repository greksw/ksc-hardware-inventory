import io
import json
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile
from ksc_inventory.result import ReportError, read_result_zip, validate_report


def fixture():
    return {
        "SchemaVersion": 1,
        "ComputerName": "PC-DEMO-01",
        "CollectedAt": "2026-10-22T07:01:45Z",
        "TotalRAMGiB": 16,
        "Modules": [
            {"Slot": "DIMM0", "Bank": "BANK0", "Manufacturer": "Example", "PartNumber": "EXAMPLE-DDR4-8G", "CapacityGiB": 8, "MemoryType": "DDR4", "SpeedMTs": 2666, "ConfiguredMTs": 2666},
            {"Slot": "DIMM1", "Bank": "BANK1", "Manufacturer": "Example", "PartNumber": "EXAMPLE-DDR4-8G", "CapacityGiB": 8, "MemoryType": "DDR4", "SpeedMTs": 2666, "ConfiguredMTs": 2666},
        ],
    }


class ResultTests(unittest.TestCase):
    def test_schema_ok(self):
        item = validate_report(json.dumps(fixture()).encode(), "PC-DEMO-01")
        self.assertEqual(len(item["Modules"]), 2)

    def test_fails_other_computer(self):
        with self.assertRaises(ReportError):
            validate_report(json.dumps(fixture()).encode(), "PC-OTHER-02")

    def test_fails_total_mismatch(self):
        data = fixture(); data["TotalRAMGiB"] = 32
        with self.assertRaises(ReportError):
            validate_report(json.dumps(data).encode(), "PC-DEMO-01")

    def test_fails_naive_datetime(self):
        data = fixture(); data["CollectedAt"] = "2026-10-22T07:01:45"
        with self.assertRaises(ReportError):
            validate_report(json.dumps(data).encode(), "PC-DEMO-01")

    def test_fails_non_finite(self):
        data = fixture(); data["Modules"][0]["CapacityGiB"] = float('nan')
        with self.assertRaises(ReportError):
            validate_report(json.dumps(data).encode(), "PC-DEMO-01")

    def test_reads_expected_archive(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "output.zip"
            with ZipFile(p, "w") as z:
                z.writestr("result/ram-PC-DEMO-01-20261022T070145Z.json", json.dumps(fixture()))
                z.writestr("result/stdout.txt", "OK")
            item, payload = read_result_zip(p, "PC-DEMO-01")
            self.assertEqual(item["TotalRAMGiB"], 16)
            self.assertEqual(json.loads(payload)["ComputerName"], "PC-DEMO-01")

    def test_rejects_traversal_member(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "output.zip"
            with ZipFile(p, "w") as z:
                z.writestr("../secrets", "do not extract")
                z.writestr("result/ram-PC-DEMO-01-20261022T070145Z.json", json.dumps(fixture()))
            with self.assertRaises(ReportError):
                read_result_zip(p, "PC-DEMO-01")

    def test_rejects_duplicate_report(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "output.zip"
            with ZipFile(p, "w") as z:
                z.writestr("result/ram-PC-DEMO-01-a.json", json.dumps(fixture()))
                z.writestr("result/ram-PC-DEMO-01-b.json", json.dumps(fixture()))
            with self.assertRaises(ReportError):
                read_result_zip(p, "PC-DEMO-01")


if __name__ == "__main__":
    unittest.main()
