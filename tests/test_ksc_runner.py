"""Offline regression tests for the SDK invocation flow, without KlAkOAPI/network."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from ksc_inventory.ksc_runner import (
    PilotError, validate_target, validate_connection, validate_collector,
    poll_action, run,
)
from test_result import fixture


GUID = "-".join(("e7bc8789", "47a9", "4ed0", "a3a7", "c68ee7061d54"))  # fabricated


class Reply:
    def __init__(self, retval=None, **fields):
        self.retval = retval
        self.fields = fields

    def RetVal(self):
        return self.retval

    def OutPar(self, field):
        return self.fields[field]


class FakeState:
    def __init__(self, done, success, delay_ms=1000):
        self.done = done
        self.success = success
        self.delay_ms = delay_ms

    def OutPar(self, field):
        return {
            "bFinalized": self.done,
            "bSuccededFinalized": self.success,
            "lNextCheckDelay": self.delay_ms,
            "lStateCode": 1 if self.success else 0,
            "pStateData": {"LastActionResult": "result/ram-report.zip"},
        }[field]


class FakeSDK:
    def __init__(self, downloaded_zip, *, host_id=GUID):
        sdk = self
        sdk.host_id = host_id
        sdk.upload_count = 0
        sdk.execute_count = 0
        sdk.download_count = 0
        sdk.access_check_count = 0
        sdk.downloaded_zip = downloaded_zip
        sdk.session_disconnected = False

        class Server:
            connected = True
            def Disconnect(self):
                sdk.session_disconnected = True

        class Agent:
            connected = True
            def UploadFile(self, url, path):
                assert sdk.session_disconnected
                sdk.upload_count += 1
            def DownloadFile(self, url, destination):
                sdk.download_count += 1
                shutil.copy(sdk.downloaded_zip, destination)

        class AdminServer:
            @staticmethod
            def Create(url, username, password, internal_user=False, verify=None):
                assert url.startswith("https://")
                assert verify.endswith(".pem")
                return Server()
            @staticmethod
            def CreateGateway(url, token, cert):
                assert token == "test-token"
                assert cert.endswith(".pem")
                return Agent()

        class HostGroup:
            def __init__(self, server): pass
            def FindHosts(self, match, fields, *_args):
                assert 'pc-demo-01.example.test' in match
                return Reply(strAccessor="faked-accessor")

        class ChunkAccessor:
            def __init__(self, server): pass
            def GetItemsCount(self, key): return Reply(retval=1)
            def GetItemsChunk(self, key, start, size):
                return Reply(pChunk={"KLCSP_ITERATOR_ARRAY": [{
                    "KLHST_WKS_HOSTNAME": sdk.host_id, "KLHST_WKS_DN": "PC-DEMO-01"
                }]})

        class CgwHelper:
            def __init__(self, server): pass
            def GetNagentLocation(self, host_id): return Reply(retval={"address": "fake"})

        class GatewayConnection:
            def __init__(self, server): pass
            def PrepareGatewayConnection(self, params):
                return Reply(wstrAuthKey="test-token")

        class NagRdu:
            def __init__(self, agent): pass
            def GetCurrentHostState(self):
                sdk.access_check_count += 1
                return Reply(retval={"status": "ok"})
            def GetUrlToUploadFileToHost(self): return Reply(retval="test-upload-url")
            def ExecuteFileAsync(self, url, executable, args):
                assert executable == "Run-RamInventory.cmd"
                sdk.execute_count += 1
                return Reply(retval="fake-action")
            def GetUrlToDownloadFileFromHost(self, result):
                assert result == "result/ram-report.zip"
                return Reply(retval="test-download-url")

        class AsyncActionStateChecker:
            def __init__(self, agent): pass
            def CheckActionState(self, action_id):
                assert action_id == "fake-action"
                return FakeState(True, True)

        sdk.KlAkAdmServer = AdminServer
        sdk.KlAkHostGroup = HostGroup
        sdk.KlAkChunkAccessor = ChunkAccessor
        sdk.KlAkCgwHelper = CgwHelper
        sdk.KlAkGatewayConnection = GatewayConnection
        sdk.KlAkNagRdu = NagRdu
        sdk.KlAkAsyncActionStateChecker = AsyncActionStateChecker
        sdk.paramParams = lambda p: p


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.ca = root / "ca.pem"
        self.ca.write_text("-----BEGIN CERTIFICATE-----\nDEMO\n-----END CERTIFICATE-----\n")
        self.collector = root / "collector.zip"
        with ZipFile(self.collector, "w") as z:
            z.writestr("utility/Run-RamInventory.cmd", "@echo off\r\n")
            z.writestr("utility/Collect-RamInventory.ps1", "Get-CimInstance Win32_PhysicalMemory\n")
        self.sha256 = hashlib.sha256(self.collector.read_bytes()).hexdigest()
        self.result = root / "result.zip"
        with ZipFile(self.result, "w") as z:
            z.writestr("result/ram-PC-DEMO-01-20261022T070145Z.json", json.dumps(fixture()))
            z.writestr("result/ram-collection-status.txt", "OK")
        self.dest_dir = root / "results"

    def args(self, mode='preflight', **overrides):
        result = dict(
            mode=mode, ksc_url="https://ksc.example.test:13299",
            ca_file=self.ca, user="ksc-inventory-user", internal_user=False,
            password_file=None, target_fqdn="pc-demo-01.example.test",
            expected_computer="PC-DEMO-01", expected_guid=GUID,
            collector=self.collector, collector_sha256=self.sha256,
            confirm_computer="PC-DEMO-01", timeout=30,
            result_dir=self.dest_dir, send=False, ssh_destination=None,
            identity=None,
        )
        result.update(overrides)
        return argparse.Namespace(**result)

    def test_validates_target(self):
        self.assertEqual(validate_target('pc-demo-01.example.test', 'PC-DEMO-01', GUID).host_id, GUID)

    def test_refuses_mismatched_fqdn(self):
        with self.assertRaises(PilotError):
            validate_target('other.example.test', 'PC-DEMO-01', GUID)

    def test_refuses_http(self):
        with self.assertRaises(PilotError):
            validate_connection('http://ksc.example.test:13299', self.ca)

    def test_refuses_127_as_url_host(self):
        with self.assertRaises(PilotError):
            validate_connection('https://127.0.0.1:13299', self.ca)

    def test_validate_collector(self):
        self.assertEqual(validate_collector(self.collector, self.sha256), self.sha256)
        with self.assertRaises(PilotError):
            validate_collector(self.collector, '0' * 64)

    def test_preflight_offline(self):
        self.assertEqual(run(self.args()), 0)

    def test_probe_no_upload_execution(self):
        sdk = FakeSDK(self.result)
        with patch('ksc_inventory.ksc_runner.get_password', return_value='test-password'):
            self.assertEqual(run(self.args('probe'), sdk=sdk), 0)
        self.assertEqual((sdk.access_check_count, sdk.upload_count, sdk.execute_count), (1, 0, 0))

    def test_wrong_guid_stops_before_gateway_and_execution(self):
        sdk = FakeSDK(self.result, host_id='-'.join(('e9de9c6d', 'bb0e', '4b43', '82c9', '199d54483448')))
        with patch('ksc_inventory.ksc_runner.get_password', return_value='test-password'):
            with self.assertRaises(PilotError):
                run(self.args('collect'), sdk=sdk)
        self.assertEqual((sdk.upload_count, sdk.execute_count), (0, 0))

    def test_collect_without_send_saves_validated_zip(self):
        sdk = FakeSDK(self.result)
        with patch('ksc_inventory.ksc_runner.get_password', return_value='test-password'):
            self.assertEqual(run(self.args('collect'), sdk=sdk), 0)
        self.assertEqual((sdk.upload_count, sdk.execute_count, sdk.download_count), (1, 1, 1))
        self.assertEqual(len(list(self.dest_dir.iterdir())), 1)

    def test_rejects_collect_wrong_confirmation(self):
        with self.assertRaises(PilotError):
            run(self.args('collect', confirm_computer='SOMEONE-ELSE'))

    def test_rejects_probe_send(self):
        with self.assertRaises(PilotError):
            run(self.args('probe', send=True))

    def test_rejects_send_without_key_before_execution(self):
        sdk = FakeSDK(self.result)
        with self.assertRaises(PilotError):
            run(self.args('collect', send=True, ssh_destination='inventory-ingest@inventory.example.test',
                          identity=Path(self.temp.name) / 'missing.key'), sdk=sdk)
        self.assertEqual(sdk.execute_count, 0)

    def test_collect_with_mocked_ssh_send(self):
        key = Path(self.temp.name) / 'ingest.key'
        key.write_text('NOT A REAL PRIVATE KEY')
        key.chmod(0o600)
        sdk = FakeSDK(self.result)
        with patch('ksc_inventory.ksc_runner.get_password', return_value='test-password'), \
             patch('ksc_inventory.ksc_runner.ssh_send', return_value='IMPORT: OK') as mocked:
            self.assertEqual(run(self.args('collect', send=True,
                                           ssh_destination='inventory-ingest@inventory.example.test',
                                           identity=key), sdk=sdk), 0)
        self.assertEqual(sdk.execute_count, 1)
        self.assertEqual(mocked.call_count, 1)
        self.assertIn(b'"ComputerName":"PC-DEMO-01"', mocked.call_args.args[0])

    def test_polling_failure_contains_action_id(self):
        class Checker:
            def CheckActionState(self, action_id): return FakeState(True, False)
        with self.assertRaisesRegex(PilotError, 'fake-action'):
            poll_action(Checker(), 'fake-action', 30)

    def test_polling_timeout_preserves_action_id(self):
        class Checker:
            def CheckActionState(self, action_id): return FakeState(False, False)
        times = iter([0, 0, 30, 30])
        with self.assertRaisesRegex(PilotError, 'fake-action'):
            poll_action(Checker(), 'fake-action', 30, clock=lambda: next(times), sleep=lambda s: None)


if __name__ == '__main__':
    unittest.main()
