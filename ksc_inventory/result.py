"""Strict, offline validation and extraction of a RAM report from a KSC ZIP.

Does not execute content from ZIP, extract arbitrary members to disk, or make
network calls. Supports the live pilot's `result/ram-*.json` layout.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
from pathlib import Path, PurePosixPath
import re
from zipfile import BadZipFile, ZipFile

MAX_COMPRESSED_ZIP = 16 * 1024 * 1024
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_UNCOMPRESSED = 32 * 1024 * 1024
MAX_ZIP_ENTRIES = 100
HOST_RE = re.compile(r"^[A-Za-z0-9_-]{1,63}$")
REPORT_RE = re.compile(r"^result/ram-[A-Za-z0-9_.-]+\.json$")


class ReportError(ValueError):
    """Report is malformed, unexpected, or not from the requested host."""


def validate_report(raw: bytes, expected_computer: str | None = None) -> dict:
    if not raw or len(raw) > MAX_JSON_BYTES:
        raise ReportError("JSON size is outside allowed range")
    try:
        obj = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReportError("Invalid UTF-8 JSON") from exc
    if not isinstance(obj, dict):
        raise ReportError("Report root must be an object")
    computer = obj.get("ComputerName")
    if not isinstance(computer, str) or not HOST_RE.fullmatch(computer):
        raise ReportError("Unexpected ComputerName")
    if expected_computer:
        if not HOST_RE.fullmatch(expected_computer):
            raise ReportError("Invalid expected computer name")
        if computer.casefold() != expected_computer.casefold():
            raise ReportError("ComputerName does not match requested host")
    stamp = obj.get("CollectedAt")
    if not isinstance(stamp, str):
        raise ReportError("CollectedAt is missing")
    try:
        parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReportError("CollectedAt is not ISO 8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ReportError("CollectedAt must contain an explicit UTC offset")
    modules = obj.get("Modules")
    if not isinstance(modules, list) or not 1 <= len(modules) <= 64:
        raise ReportError("Modules must contain 1..64 DIMMs")
    total_from_modules = 0.0
    for number, module in enumerate(modules, 1):
        if not isinstance(module, dict):
            raise ReportError(f"Module {number} is not an object")
        cap = module.get("CapacityGiB")
        if isinstance(cap, bool) or not isinstance(cap, (int, float)):
            raise ReportError(f"Module {number} has invalid capacity")
        if not math.isfinite(cap) or not (0 < cap <= 2048):
            raise ReportError(f"Module {number} capacity out of range")
        total_from_modules += cap
        for field in ("Slot", "Bank", "Manufacturer", "PartNumber", "MemoryType"):
            value = module.get(field)
            if value is not None and (not isinstance(value, str) or len(value) > 512):
                raise ReportError(f"Module {number} has invalid {field}")
        for field in ("SpeedMTs", "ConfiguredMTs"):
            value = module.get(field)
            if value is not None and (isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 50000):
                raise ReportError(f"Module {number} has invalid {field}")
    total = obj.get("TotalRAMGiB")
    if isinstance(total, bool) or not isinstance(total, (int, float)):
        raise ReportError("Missing or invalid TotalRAMGiB")
    if not math.isfinite(total) or not (0 < total <= 131072):
        raise ReportError("TotalRAMGiB outside allowed range")
    if abs(total_from_modules - total) > (0.03 * len(modules) + 0.05):
        raise ReportError("TotalRAMGiB differs from DIMM capacities")
    return obj


def read_result_zip(zip_path: Path, expected_computer: str | None = None) -> tuple[dict, bytes]:
    zip_path = zip_path.expanduser().resolve(strict=True)
    if not zip_path.is_file() or zip_path.stat().st_size > MAX_COMPRESSED_ZIP:
        raise ReportError("ZIP missing or exceeds size limit")
    try:
        with ZipFile(zip_path) as z:
            entries = z.infolist()
            if not entries or len(entries) > MAX_ZIP_ENTRIES:
                raise ReportError("Unexpected number of ZIP entries")
            uncompressed = 0
            candidates = []
            for info in entries:
                name = info.filename
                path = PurePosixPath(name)
                if ("\\" in name or name.startswith("/") or ".." in path.parts or
                        len(name) > 256 or ":" in name):
                    raise ReportError("Unsafe ZIP member name")
                if info.flag_bits & 0x1:
                    raise ReportError("Encrypted ZIP entries are not accepted")
                uncompressed += info.file_size
                if uncompressed > MAX_UNCOMPRESSED:
                    raise ReportError("ZIP inflated content exceeds limit")
                if REPORT_RE.fullmatch(name):
                    if info.file_size > MAX_JSON_BYTES:
                        raise ReportError("JSON member exceeds size limit")
                    candidates.append(info)
            if len(candidates) != 1:
                raise ReportError("Expected exactly one result/ram-*.json in ZIP")
            with z.open(candidates[0]) as f:
                raw = f.read(MAX_JSON_BYTES + 1)
    except BadZipFile as exc:
        raise ReportError("Invalid ZIP") from exc
    report = validate_report(raw, expected_computer)
    # Canonical JSON ensures the receiver sees only validated report data.
    payload = json.dumps(report, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if len(payload) > MAX_JSON_BYTES:
        raise ReportError("Canonical JSON exceeds limit")
    return report, payload


def main() -> int:
    p = argparse.ArgumentParser(description="Validate offline KSC RAM inventory ZIP")
    p.add_argument("zip", type=Path)
    p.add_argument("--expected-computer", required=True)
    args = p.parse_args()
    try:
        report, _ = read_result_zip(args.zip, args.expected_computer)
    except (ReportError, OSError) as exc:
        p.exit(2, f"INVALID REPORT: {exc}\n")
    print(f"OK Computer={report['ComputerName']} CollectedAt={report['CollectedAt']} "
          f"Modules={len(report['Modules'])} RAM={report['TotalRAMGiB']} GiB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
