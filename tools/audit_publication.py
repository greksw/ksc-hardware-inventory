#!/usr/bin/env python3
"""Conservative public GitHub preflight: reject obvious internal data/secrets.

When inside Git, scan all currently tracked and untracked-not-ignored files,
not only the last commit. This is NOT a guarantee of safe publication.
"""
from __future__ import annotations

import argparse
import ipaddress
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", ".idea", ".vscode", "vendor"}
SKIP_SUFFIXES = {".png", ".jpg", ".gif", ".pdf", ".zip", ".pyc"}
BLOCK_SUFFIXES = {".pem", ".cer", ".crt", ".key", ".prk", ".pfx", ".p12", ".sqlite", ".sqlite3", ".db", ".xlsx", ".csv", ".zip"}
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
PATTERNS = [
    ("internal host namespace", re.compile(r"(?i)\b[A-Za-z0-9.-]+\.(?:loc|local|lan|internal)\b")),
    ("internal AD namespace", re.compile(r"(?i)\bad\.[a-z][a-z0-9-]+\.[a-z]{2,}\b")),
    ("private key text", re.compile(r"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----")),
    ("authentication credential literal", re.compile(r"(?i)\b(?:password|api[_-]?token|api[_-]?key|secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]")),
    ("SSH root destination", re.compile(r"(?i)\broot@[a-z0-9.-]+")),
    ("UUID device identifier", re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")),
]
CODE_SUFFIXES = {".py", ".ps1", ".cmd", ".sh", ".bat", ".yml", ".yaml"}
CODE_PATTERNS = [
    ("disabled TLS validation", re.compile(r"\bverify\s*=\s*False\b")),
    ("disabled SSH host verification", re.compile(r"(?i)StrictHostKeyChecking\s*[= ]\s*no\b")),
    ("shell password interpolation", re.compile(r"(?i)" + "ssh" + "pass" + r"\b")),
]


def files_for_audit(root: Path = ROOT):
    try:
        p = subprocess.run(["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                           check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return sorted(f for f in root.rglob("*") if f.is_file() and not any(x in SKIP_DIRS for x in f.relative_to(root).parts))
    names = [n.decode("utf-8") for n in p.stdout.split(b"\0") if n]
    return sorted({root / n for n in names})


def validate(files, root: Path = ROOT):
    failures = []
    inspected = 0
    for path in files:
        rel = path.relative_to(root)
        if any(p in SKIP_DIRS for p in rel.parts):
            continue
        if not path.is_file():
            continue
        if path.suffix.lower() in BLOCK_SUFFIXES or path.name in {"known_hosts", ".env"}:
            failures.append(f"{rel}: file type must not be published")
            continue
        if path.stat().st_size > 2 * 1024 * 1024:
            failures.append(f"{rel}: unexpectedly large file")
            continue
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeError:
            failures.append(f"{rel}: unexpected binary content")
            continue
        inspected += 1
        for index, line in enumerate(content.splitlines(), 1):
            for m in IP_RE.finditer(line):
                try:
                    addr = ipaddress.ip_address(m.group(0))
                except ValueError:
                    continue
                if addr == ipaddress.ip_address("127.0.0.1"):
                    continue
                if addr in ipaddress.ip_network("192.0.2.0/24") or addr in ipaddress.ip_network("198.51.100.0/24") or addr in ipaddress.ip_network("203.0.113.0/24"):
                    continue
                failures.append(f"{rel}:{index}: literal IP address must be anonymized")
            for label, pattern in PATTERNS:
                if rel.name == ".gitignore" and label == "internal host namespace":
                    continue
                if pattern.search(line):
                    failures.append(f"{rel}:{index}: {label}")
            if path.suffix.lower() in CODE_SUFFIXES:
                for label, pattern in CODE_PATTERNS:
                    if pattern.search(line):
                        failures.append(f"{rel}:{index}: {label}")
    return inspected, failures


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-dir", type=Path, default=ROOT,
                        help="Scan a private staging directory without copying it into Git")
    args = parser.parse_args()
    scan_root = args.scan_dir.expanduser().resolve(strict=True)
    if not scan_root.is_dir():
        parser.error("--scan-dir must be a directory")
    n, errors = validate(files_for_audit(scan_root), scan_root)
    print(f"PUBLICATION AUDIT: scanned {n} text files")
    if errors:
        for e in errors:
            print(f"BLOCKED: {e}")
        sys.exit(1)
    print("No obvious leaks found. MANUAL DIFF AND HISTORY REVIEW REQUIRED.")
