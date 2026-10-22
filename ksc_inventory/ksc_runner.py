"""Single-host KSC 15.1 Open API RAM inventory runner.

Adapted from an operator-verified one-host pilot. The underlying Kaspersky
KlAkOAPI SDK is vendor-supplied and intentionally not bundled. Run only on
approved endpoints. Default preflight performs no network connection.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
from getpass import getpass
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import sys
import time
from urllib.parse import urlsplit
from uuid import UUID
from zipfile import BadZipFile, ZipFile

from .result import read_result_zip, ReportError
from .import_result import DEST_RE, send as ssh_send

FQDN_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
HOST_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,63}$")
EXPECTED_MEMBERS = {
    "utility/Run-RamInventory.cmd",
    "utility/Collect-RamInventory.ps1",
}


class PilotError(RuntimeError):
    """Unsuccessful or unsafe KSC pilot operation."""


@dataclass(frozen=True)
class Target:
    fqdn: str
    computer: str
    host_id: str


def validate_connection(url: str, ca_file: Path) -> None:
    """Require a real HTTPS DNS name and a user-supplied trust anchor."""
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or
            not FQDN_PATTERN.fullmatch(parsed.hostname) or
            parsed.username is not None or parsed.password is not None or
            parsed.path not in ("", "/") or parsed.query or parsed.fragment or
            parsed.port != 13299):
        raise PilotError("KSC URL must be https://dns-name:13299 (DNS name must match certificate SAN)")
    try:
        ipaddress.ip_address(parsed.hostname)
    except ValueError:
        pass
    else:
        raise PilotError("KSC hostname must be a certificate-matching DNS name, not an IP address")
    if not ca_file.is_file() or not ca_file.read_bytes().startswith(b"-----BEGIN CERTIFICATE-----"):
        raise PilotError("CA PEM trust anchor missing or not PEM")


def validate_target(fqdn: str, computer: str, guid: str) -> Target:
    if not FQDN_PATTERN.fullmatch(fqdn):
        raise PilotError("Target must be a plain DNS FQDN")
    if not HOST_PATTERN.fullmatch(computer):
        raise PilotError("Computer name is invalid")
    if fqdn.split(".", 1)[0].casefold() != computer.casefold():
        raise PilotError("FQDN short name does not match expected computer")
    try:
        parsed = UUID(guid)
        if parsed.version is None:
            raise ValueError("invalid UUID")
    except (ValueError, AttributeError) as exc:
        raise PilotError("Expected KSC GUID must be a valid UUID") from exc
    return Target(fqdn=fqdn, computer=computer.upper(), host_id=str(parsed))


def validate_collector(path: Path, expected_sha256: str | None = None) -> str:
    if not path.is_file() or not 0 < path.stat().st_size <= 1024 * 1024:
        raise PilotError("Collector ZIP is absent or too large")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if expected_sha256:
        if not re.fullmatch(r"[a-fA-F0-9]{64}", expected_sha256):
            raise PilotError("Collector SHA256 must be 64 hex digits")
        if digest != expected_sha256.lower():
            raise PilotError("Collector SHA256 does not match approved hash")
    try:
        with ZipFile(path) as archive:
            if set(archive.namelist()) != EXPECTED_MEMBERS or len(archive.infolist()) != 2:
                raise PilotError("Collector must contain exactly two approved utility/ files")
            if any(i.file_size > 256 * 1024 or i.flag_bits & 1 for i in archive.infolist()):
                raise PilotError("Collector contains unexpectedly large/encrypted files")
            if archive.testzip() is not None:
                raise PilotError("Collector ZIP checksum failed")
    except BadZipFile as exc:
        raise PilotError("Collector ZIP is corrupt") from exc
    return digest


def find_verified_host(server, sdk, target: Target) -> str:
    """Return host ID only when KSC returns exactly one matching host."""
    hg = sdk.KlAkHostGroup(server)
    accessor = sdk.KlAkChunkAccessor(server)
    response = hg.FindHosts(
        f'(KLHST_WKS_FQDN="{target.fqdn}")',
        ["KLHST_WKS_HOSTNAME", "KLHST_WKS_DN"],
        [],
        {"KLGRP_FIND_FROM_CUR_VS_ONLY": True},
        60,
    )
    accessor_id = response.OutPar("strAccessor")
    count = int(accessor.GetItemsCount(accessor_id).RetVal())
    if count != 1:
        raise PilotError(f"Refusing target selection: FindHosts returned {count} matches")
    chunk = accessor.GetItemsChunk(accessor_id, 0, 1)
    entry = chunk.OutPar("pChunk")["KLCSP_ITERATOR_ARRAY"][0]
    # In the verified 15.1 SDK response this field holds the endpoint host GUID.
    found_id = str(entry["KLHST_WKS_HOSTNAME"])
    display_name = str(entry["KLHST_WKS_DN"])
    if found_id.casefold() != target.host_id.casefold():
        raise PilotError("Refusing target: KSC host ID differs from approved GUID")
    if display_name.casefold() != target.computer.casefold():
        raise PilotError("Refusing target: KSC computer name differs from approved computer")
    print(f"HOST VERIFIED: {display_name} / GUID matches")
    return found_id


def make_gateway(server, sdk, host_id: str, url: str, ca_file: Path):
    helper = sdk.KlAkCgwHelper(server)
    location = helper.GetNagentLocation(host_id).RetVal()
    gateway = sdk.KlAkGatewayConnection(server)
    response = gateway.PrepareGatewayConnection([sdk.paramParams(location)])
    token = response.OutPar("wstrAuthKey")
    if not token:
        raise PilotError("KSC returned empty gateway token")
    # Required by the verified KSC pilot before creation of agent connection.
    server.Disconnect()
    print("Gateway prepared; primary session disconnected")
    agent = sdk.KlAkAdmServer.CreateGateway(url, token, str(ca_file))
    if not agent.connected:
        raise PilotError("Network Agent gateway connection failed")
    print("NETWORK AGENT: connected with verified TLS")
    return agent


def poll_action(checker, action_id: str, timeout_sec: int, clock=time.monotonic, sleep=time.sleep):
    """Return successful pStateData; never treat action acceptance as success."""
    deadline = clock() + timeout_sec
    while clock() < deadline:
        state = checker.CheckActionState(action_id)
        finalized = bool(state.OutPar("bFinalized"))
        if finalized:
            code = state.OutPar("lStateCode")
            if not bool(state.OutPar("bSuccededFinalized")):
                raise PilotError(f"KSC action finalized unsuccessfully (state={code}); action ID={action_id}. Do not rerun blindly")
            print(f"ASYNC: finalized successfully (state={code})")
            return state.OutPar("pStateData")
        try:
            delay_ms = int(state.OutPar("lNextCheckDelay"))
        except (ValueError, TypeError, KeyError):
            delay_ms = 3000
        print("ASYNC: running", flush=True)
        sleep(min(max(delay_ms / 1000.0, 0.5), 10.0, max(0.0, deadline - clock())))
    raise PilotError(f"KSC action not finalized within {timeout_sec}s; action ID={action_id}. Do not rerun blindly")


def last_result_path(data) -> str:
    try:
        item = data.Get("LastActionResult")
    except (AttributeError, KeyError, TypeError):
        item = None
    if not item:
        try:
            item = data["LastActionResult"]
        except (KeyError, TypeError):
            pass
    if not isinstance(item, str) or not item:
        raise PilotError("Completed KSC action has no LastActionResult")
    return item


def save_result(rdu, agent, remote_file: str, output_dir: Path, computer: str) -> Path:
    if output_dir.is_symlink():
        raise PilotError("Refusing symlink result directory")
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_dir.chmod(0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = output_dir / f"{computer}-ram-result-{stamp}.zip"
    if output.exists():
        raise PilotError("Result destination already exists")
    url = rdu.GetUrlToDownloadFileFromHost(remote_file).RetVal()
    previous_umask = os.umask(0o077)
    try:
        agent.DownloadFile(url, str(output))
    finally:
        os.umask(previous_umask)
    output.chmod(0o600)
    return output


def load_sdk():
    # Late import: preflight and offline unit tests need no proprietary SDK.
    from types import SimpleNamespace
    from KlAkOAPI.AdmServer import KlAkAdmServer
    from KlAkOAPI.HostGroup import KlAkHostGroup
    from KlAkOAPI.ChunkAccessor import KlAkChunkAccessor
    from KlAkOAPI.CgwHelper import KlAkCgwHelper
    from KlAkOAPI.GatewayConnection import KlAkGatewayConnection
    from KlAkOAPI.NagRdu import KlAkNagRdu
    from KlAkOAPI.AsyncActionStateChecker import KlAkAsyncActionStateChecker
    from KlAkOAPI.Params import paramParams
    return SimpleNamespace(
        KlAkAdmServer=KlAkAdmServer, KlAkHostGroup=KlAkHostGroup,
        KlAkChunkAccessor=KlAkChunkAccessor, KlAkCgwHelper=KlAkCgwHelper,
        KlAkGatewayConnection=KlAkGatewayConnection, KlAkNagRdu=KlAkNagRdu,
        KlAkAsyncActionStateChecker=KlAkAsyncActionStateChecker, paramParams=paramParams,
    )


def get_password(password_file: Path | None) -> str:
    if password_file is None:
        return getpass("KSC API password: ")
    if password_file.stat().st_mode & 0o077:
        raise PilotError("KSC password file must be owner-readable only (mode 0600)")
    password = password_file.read_text(encoding="utf-8").rstrip("\r\n")
    if not password:
        raise PilotError("KSC password file is empty")
    return password


def command_parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode", choices=("preflight", "probe", "collect"), default="preflight")
    p.add_argument("--ksc-url", default=os.environ.get("KSC_URL"), required=False)
    p.add_argument("--ca-file", type=Path, default=os.environ.get("KSC_CA_FILE"))
    p.add_argument("--user", default=os.environ.get("KSC_USER"))
    p.add_argument("--internal-user", action="store_true", help="Only for KSC internal accounts (never assume automatically)")
    p.add_argument("--password-file", type=Path, help="Local mode 0600 file; otherwise interactive getpass")
    p.add_argument("--target-fqdn", default=os.environ.get("KSC_TARGET_FQDN"))
    p.add_argument("--expected-computer", default=os.environ.get("KSC_EXPECTED_COMPUTER"))
    p.add_argument("--expected-guid", default=os.environ.get("KSC_EXPECTED_GUID"))
    p.add_argument("--collector", type=Path)
    p.add_argument("--collector-sha256", help="Required for collect; compare with approved ZIP fingerprint")
    p.add_argument("--confirm-computer", help="Required for collect; must equal the approved computer name")
    p.add_argument("--timeout", type=int, default=180)
    p.add_argument("--result-dir", type=Path, default=Path.home() / ".local/share/ksc-hardware-inventory/results")
    p.add_argument("--send", action="store_true", help="After successful collect and ZIP validation, import over SSH")
    p.add_argument("--ssh-destination", help="inventory-ingest@host; forced command on receiver")
    p.add_argument("--identity", type=Path, help="Dedicated SSH private key; required with --send")
    return p


def validate_args(args) -> Target:
    if not all((args.ksc_url, args.ca_file, args.user, args.target_fqdn, args.expected_computer, args.expected_guid)):
        raise PilotError("KSC URL, CA file, user, target FQDN, expected computer and GUID are all required")
    ca = Path(args.ca_file).expanduser()
    validate_connection(args.ksc_url, ca)
    target = validate_target(args.target_fqdn, args.expected_computer, args.expected_guid)
    if args.timeout < 15 or args.timeout > 3600:
        raise PilotError("Timeout must be 15..3600 seconds")
    if args.send and (args.mode != "collect" or not args.identity or not args.ssh_destination):
        raise PilotError("--send requires --mode collect, --identity, and --ssh-destination")
    if args.send:
        if not DEST_RE.fullmatch(args.ssh_destination):
            raise PilotError("SSH destination must be inventory-ingest@host")
        identity = args.identity.expanduser()
        if not identity.is_file() or identity.stat().st_mode & 0o077:
            raise PilotError("SSH identity must exist and be mode 0600")
    if args.mode == "collect":
        if args.confirm_computer != target.computer:
            raise PilotError("Refusing execution: --confirm-computer must exactly match expected computer")
        if not args.collector or not args.collector_sha256:
            raise PilotError("Collect mode needs a reviewed --collector ZIP and its approved --collector-sha256")
        validate_collector(args.collector.expanduser(), args.collector_sha256)
    if args.mode == "preflight" and args.collector:
        digest = validate_collector(args.collector.expanduser(), args.collector_sha256)
        print(f"COLLECTOR SHA256: {digest}")
    return target


def run(args, sdk=None):
    target = validate_args(args)
    if args.mode == "preflight":
        print("PREFLIGHT OK: no KSC/SSH connection made")
        return 0

    sdk = sdk or load_sdk()
    password = get_password(args.password_file)
    try:
        server = sdk.KlAkAdmServer.Create(
            args.ksc_url, args.user, password,
            internal_user=args.internal_user, verify=str(Path(args.ca_file).expanduser()),
        )
    finally:
        del password
    if not server.connected:
        raise PilotError("KSC API session not connected")
    print("KSC API: connected with verified TLS")
    host_id = find_verified_host(server, sdk, target)
    agent = make_gateway(server, sdk, host_id, args.ksc_url, Path(args.ca_file).expanduser())
    rdu = sdk.KlAkNagRdu(agent)
    if args.mode == "probe":
        state = rdu.GetCurrentHostState()
        if state.RetVal() is None:
            raise PilotError("NagRdu.GetCurrentHostState returned empty result")
        print("NAGRDU PROBE: OK (read-only, no collector execution)")
        return 0

    print(f"APPROVED TARGET: {target.computer}; COLLECTOR SHA256: {args.collector_sha256.lower()}")
    upload_url = rdu.GetUrlToUploadFileToHost().RetVal()
    agent.UploadFile(upload_url, str(args.collector.expanduser()))
    print("COLLECTOR: uploaded")
    action_id = rdu.ExecuteFileAsync(upload_url, "Run-RamInventory.cmd", "").RetVal()
    print(f"REMOTE ACTION ID: {action_id}")
    if not action_id:
        raise PilotError("KSC did not return an action ID")
    checker = sdk.KlAkAsyncActionStateChecker(agent)
    state_data = poll_action(checker, action_id, args.timeout)
    remote_file = last_result_path(state_data)
    output = save_result(rdu, agent, remote_file, args.result_dir.expanduser(), target.computer)
    print(f"RESULT ZIP: {output}")
    try:
        report, payload = read_result_zip(output, target.computer)
    except ReportError as exc:
        raise PilotError(f"Downloaded report is invalid: {exc}") from exc
    print(f"RESULT VERIFIED: computer={report['ComputerName']} modules={len(report['Modules'])} total={report['TotalRAMGiB']}GiB")
    if args.send:
        # No user-supplied remote command: restricted authorized_keys decides.
        reply = ssh_send(payload, args.ssh_destination, args.identity.expanduser())
        print(reply)
        print("INVENTORY IMPORT: OK")
    else:
        print("IMPORT SKIPPED: use --send explicitly after validating receiver")
    return 0


def main(argv=None) -> int:
    args = command_parser().parse_args(argv)
    try:
        return run(args)
    except (PilotError, ReportError, OSError, TimeoutError, ValueError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        # Vendor SDK exceptions may contain tokens/headers; do not echo them.
        print(f"ERROR: KSC SDK failed ({type(exc).__name__}); inspect privately", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
