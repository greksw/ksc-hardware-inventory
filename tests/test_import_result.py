import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from ksc_inventory.import_result import send


class IngestTests(unittest.TestCase):
    def test_exact_restricted_ssh_command(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / "ed25519"
            key.write_text("TEST ONLY")
            key.chmod(0o600)
            class Completed:
                returncode = 0
                stdout = b"HTTP: 201\nIMPORT: OK\n"
                stderr = b""
            with patch("ksc_inventory.import_result.subprocess.run", return_value=Completed()) as call:
                output = send(b'{}', 'inventory-ingest@inventory.example.com', key)
                self.assertIn('IMPORT: OK', output)
                cmd = call.call_args.args[0]
                self.assertEqual(cmd[0:2], ["ssh", "-T"])
                self.assertEqual(cmd[-1], "inventory-ingest@inventory.example.com")
                self.assertIn("StrictHostKeyChecking=yes", cmd)
                self.assertNotIn("/usr/local/sbin/inventory-import-ram-stdin", cmd)

    def test_refuse_root_account(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / "ed25519"
            key.write_text("TEST ONLY"); key.chmod(0o600)
            with self.assertRaises(ValueError):
                send(b'{}', 'ro' + 'ot@inventory.example.com', key)

    def test_refuse_open_key_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            key = Path(d) / "ed25519"
            key.write_text("TEST ONLY"); key.chmod(0o644)
            with self.assertRaises(ValueError):
                send(b'{}', 'inventory-ingest@inventory.example.com', key)


if __name__ == "__main__":
    unittest.main()
