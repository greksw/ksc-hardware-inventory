#!/usr/bin/env python3
"""Read-only KSC 15.1 host metadata audit (v0.3.2); no remote execution.

Run from the ksc-hardware-inventory repo with the vendor KlAkOAPI SDK in
PYTHONPATH. Outputs a private JSON report and non-identifying console summary.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from getpass import getpass
import json
import os
from pathlib import Path
import sys

from ksc_inventory.ksc_runner import validate_connection

FIELDS = [
    "KLHST_WKS_HOSTNAME",           # KSC unique host ID, NOT NetBIOS name
    "KLHST_WKS_DN",                 # KSC display name
    "KLHST_WKS_FQDN",               # DNS name
    "KLHST_WKS_OS_NAME",            # OS as reported by KSC
    "KLHST_WKS_STATUS",             # bit mask: visible=1, agent installed=4, alive=8
    "KLHST_WKS_CTYPE",              # network computer type flags; NOT reliable OS edition
    "HST_VM_TYPE",                  # 0 unknown, 2 physical, other != physical
    "KLHST_WKS_GROUPID",
    "KLHST_WKS_LAST_NAGENT_CONNECTED",
]


def value(obj, key):
    """Read optional SDK paramParams fields without coercing missing to zero."""
    # KSC KlAkParams may omit optional fields.
    # Check membership before accessing a typed value.
    get_names = getattr(obj, "GetNames", None)
    if callable(get_names) and key not in get_names():
        return None

    try:
        return obj[key]
    except (KeyError, LookupError, TypeError, AttributeError):
        pass
    try:
        return obj.GetValue(key)
    except (KeyError, LookupError, TypeError, AttributeError):
        return None


def integer(obj):
    if obj is None or isinstance(obj, bool):
        return None
    try:
        return int(obj)
    except (TypeError, ValueError):
        return None


def classify(record):
    status = integer(record.get("KLHST_WKS_STATUS"))
    computer_type = integer(record.get("KLHST_WKS_CTYPE"))
    vm_type = integer(record.get("HST_VM_TYPE"))
    os_name = str(record.get("KLHST_WKS_OS_NAME") or "")

    agent_installed = None if status is None else bool(status & 4)
    agent_alive = None if status is None else bool(status & 8)
    visible = None if status is None else bool(status & 1)
    # The CTYPE bits describe network/computer roles, not the edition of Windows.
    # Workstations can legitimately advertise both bit 0 and bit 1 (e.g. 4099).
    ctype_workstation_bit = None if computer_type is None else bool(computer_type & 1)
    ctype_server_bit = None if computer_type is None else bool(computer_type & 2)
    normalized_os = " ".join(os_name.casefold().split())
    is_windows = "windows" in normalized_os if os_name else None
    # Conservative, intentionally narrow: never infer eligibility from CTYPE alone.
    is_server = None
    is_workstation = None
    if normalized_os.startswith("microsoft windows server ") or normalized_os == "microsoft windows server":
        is_server, is_workstation = True, False
    elif normalized_os in ("microsoft windows 10", "microsoft windows 11"):
        is_server, is_workstation = False, True
    physical = True if vm_type == 2 else (False if vm_type not in (None, 0) else None)
    # This is a *suggestion for manual review*, never authorization to execute.
    # Unknown OS editions and all Windows Server releases are excluded.
    candidate = all(x is True for x in (agent_installed, agent_alive, visible, is_workstation, is_windows, physical)) and is_server is False

    return {
        "visible": visible,
        "agent_installed": agent_installed,
        "agent_alive": agent_alive,
        "windows": is_windows,
        "workstation": is_workstation,
        "server": is_server,
        "ctype_workstation_bit": ctype_workstation_bit,
        "ctype_server_bit": ctype_server_bit,
        "physical": physical,
        "review_candidate_only": candidate,
    }


def transform(entry):
    data = {}
    for field in FIELDS:
        raw = value(entry, field)
        if field in ("KLHST_WKS_STATUS", "KLHST_WKS_CTYPE", "HST_VM_TYPE", "KLHST_WKS_GROUPID"):
            data[field] = integer(raw)
        else:
            data[field] = None if raw is None else str(raw)
    data["classification"] = classify(data)
    return data


def summary(records, total):
    c = Counter()
    categories = ("visible", "agent_installed", "agent_alive", "windows", "workstation", "server", "physical", "ctype_workstation_bit", "ctype_server_bit")
    for rec in records:
        state = rec["classification"]
        c["review_candidates"] += bool(state["review_candidate_only"])
        for key in categories:
            suffix = "unknown" if state[key] is None else ("true" if state[key] else "false")
            c[f"{key}_{suffix}"] += 1
    totals = {f"{key}_{suffix}": c[f"{key}_{suffix}"] for key in categories for suffix in ("true", "false", "unknown")}
    return {
        "ksc_total_hosts": total,
        "rows_examined": len(records),
        "partial_sample": len(records) < total,
        "review_candidates": c["review_candidates"],
        **totals,
    }


def query_hosts(server, host_group_class, chunk_accessor_class, limit, batch_size):
    group = host_group_class(server)
    accessor = chunk_accessor_class(server)
    token = None
    try:
        # Empty filter means all hosts in the current KSC server scope.
        reply = group.FindHosts("", FIELDS, [], {"KLGRP_FIND_FROM_CUR_VS_ONLY": True}, 600)
        token = reply.OutPar("strAccessor")
        if not token:
            raise RuntimeError("empty host accessor")
        total = int(accessor.GetItemsCount(token).RetVal())
        if total < 0:
            raise RuntimeError("invalid KSC host count")
        records = []
        target = min(total, limit)
        for start in range(0, target, batch_size):
            count = min(batch_size, target - start)
            reply = accessor.GetItemsChunk(token, start, count)
            chunk = reply.OutPar("pChunk")["KLCSP_ITERATOR_ARRAY"]
            if len(chunk) != count:
                raise RuntimeError("short chunk; refusing incomplete audit")
            records.extend(transform(row) for row in chunk)
        return total, records
    finally:
        if token:
            accessor.Release(token)


def private_write(output_dir, payload):
    if output_dir.is_symlink():
        raise RuntimeError("output directory must not be a symlink")
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_dir.chmod(0o700)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = output_dir / f"ksc-host-audit-{stamp}-{os.getpid()}.json"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--ksc-url", default=os.environ.get("KSC_URL"))
    p.add_argument("--ca-file", type=Path, default=os.environ.get("KSC_CA_FILE"))
    p.add_argument("--user", default=os.environ.get("KSC_USER"))
    p.add_argument("--password-file", type=Path, help="optional private file (mode 0600)")
    p.add_argument("--limit", type=int, default=50, help="maximum number of records to inspect (default 50)")
    p.add_argument("--batch-size", type=int, default=50)
    p.add_argument("--output-dir", type=Path, default=Path.home() / ".local/share/ksc-hardware-inventory/audit")
    return p


def execute(args, sdk=None, password=None):
    if not args.ksc_url or not args.ca_file or not args.user:
        raise ValueError("KSC_URL, KSC_CA_FILE, KSC_USER are required")
    validate_connection(args.ksc_url, args.ca_file.expanduser())
    if not 1 <= args.limit <= 5000 or not 1 <= args.batch_size <= 100:
        raise ValueError("limit must be 1..5000 and batch-size 1..100")

    if sdk is None:
        from KlAkOAPI.AdmServer import KlAkAdmServer
        from KlAkOAPI.HostGroup import KlAkHostGroup
        from KlAkOAPI.ChunkAccessor import KlAkChunkAccessor
        sdk = (KlAkAdmServer, KlAkHostGroup, KlAkChunkAccessor)
    if password is None:
        if args.password_file:
            password_file = args.password_file.expanduser()
            if password_file.stat().st_mode & 0o077:
                raise ValueError("password file must have mode 0600")
            password = password_file.read_text(encoding="utf-8").rstrip("\r\n")
        else:
            password = getpass("KSC API password: ")
    if not password:
        raise ValueError("empty password")

    admin_server, host_group_class, accessor_class = sdk
    server = None
    try:
        server = admin_server.Create(args.ksc_url, args.user, password, internal_user=False,
                                     verify=str(args.ca_file.expanduser()))
        password = None
        if not server.connected:
            raise RuntimeError("KSC authentication did not connect")
        print("KSC connected (TLS verified). Reading host metadata only.")
        total, records = query_hosts(server, host_group_class, accessor_class, args.limit, args.batch_size)
    finally:
        password = None
        if server is not None:
            try:
                server.Disconnect()
            except Exception:
                pass

    report = {
        "schema": "ksc-host-audit-v0.3.2",
        "collected_at_utc": datetime.now(timezone.utc).isoformat(),
        "read_only": True,
        "classification_note": "Workstation/server classification uses explicit Windows OS name, not CTYPE bits. Candidates require manual approval.",
        "scope": "current KSC virtual server; FindHosts only",
        "summary": summary(records, total),
        "hosts": records,
    }
    path = private_write(args.output_dir.expanduser(), report)
    print("===== AUDIT SUMMARY (NO HOST IDENTIFIERS) =====")
    for key, val in report["summary"].items():
        print(f"{key}: {val}")
    print("PRIVATE JSON:", path)
    print("No execution, upload, SSH, or Inventory API writes were performed.")
    return report


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        execute(args)
        return 0
    except Exception as exc:
        # Do not expose SDK exception details, which may contain auth headers.
        print(f"ERROR: audit failed ({type(exc).__name__}); inspect privately", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
