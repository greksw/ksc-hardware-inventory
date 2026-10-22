"""Send validated JSON through a restricted, host-key-verified SSH ingest account.

By default it only validates the report. Actual delivery requires --send.
The server's authorized_keys must force the exact importer command.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys
from .result import read_result_zip, ReportError

DEST_RE = re.compile(r"^inventory-ingest@[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")


def send(payload: bytes, destination: str, identity: Path, *, timeout: int = 30) -> str:
    if not DEST_RE.fullmatch(destination):
        raise ValueError("Destination must use dedicated inventory-ingest@hostname or IPv4")
    identity = identity.expanduser().resolve(strict=True)
    if not identity.is_file():
        raise ValueError("SSH identity is not a file")
    if identity.stat().st_mode & 0o077:
        raise ValueError("SSH private key must not be group/world accessible")
    # Deliberately no remote command: authorized_keys enforces forced command.
    cmd = [
        "ssh", "-T", "-i", str(identity),
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "PasswordAuthentication=no",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "ConnectTimeout=10",
        destination,
    ]
    completed = subprocess.run(cmd, input=payload, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=timeout, check=False)
    if completed.returncode:
        # Avoid printing raw remote stderr: it may contain internal topology.
        raise RuntimeError(f"SSH ingest returned failure status {completed.returncode}")
    out = completed.stdout.decode("utf-8", errors="replace").strip()
    if "IMPORT: OK" not in out:
        raise RuntimeError("Receiver did not confirm IMPORT: OK")
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("zip", type=Path)
    p.add_argument("--expected-computer", required=True)
    p.add_argument("--ssh-destination", required=True)
    p.add_argument("--identity", type=Path, required=True)
    p.add_argument("--send", action="store_true", help="Explicitly transmit the validated report")
    a = p.parse_args()
    try:
        report, payload = read_result_zip(a.zip, a.expected_computer)
        print(f"VALIDATED: {report['ComputerName']} / {len(report['Modules'])} DIMMs")
        if not a.send:
            print("DRY RUN: no SSH connection made. Add --send to import.")
            return 0
        print(send(payload, a.ssh_destination, a.identity))
        return 0
    except (ValueError, OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
        print(f"ERROR: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
