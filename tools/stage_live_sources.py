#!/usr/bin/env python3
"""Copy exactly 3 existing operational scripts to a PRIVATE folder for comparison.

This script does NOT anonymize or publish them. Output must be outside repository.
It does not copy results, certificate files, ZIPs, SDK, backups, or passwords.
"""
import argparse
import os
from pathlib import Path
import shutil

REPOSITORY = Path(__file__).resolve().parents[1]
SOURCE_FILES = ("gateway_probe.py", "ram_pilot.py", "import_result.py")


def stage(src: Path, dest: Path) -> None:
    src = src.expanduser().resolve(strict=True)
    dest = dest.expanduser().resolve()
    if src == dest or src in dest.parents or dest in src.parents or dest == REPOSITORY or REPOSITORY in dest.parents:
        raise ValueError("Private review destination must be separate from live source")
    if (dest / ".git").exists() or any(parent.name == ".git" for parent in dest.parents):
        raise ValueError("Do not put private sources into a Git repository")
    if dest.exists() and any(dest.iterdir()):
        raise ValueError("Private staging directory must be empty")
    dest.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(dest, 0o700)
    for name in SOURCE_FILES:
        f = src / name
        if not f.is_file() or f.is_symlink():
            raise FileNotFoundError(f"Missing or symlinked operational script: {f}")
        target = dest / name
        shutil.copyfile(f, target)
        os.chmod(target, 0o600)
        print(f"Private copy staged: {target}")
    print("Staged sources are NOT sanitized: do NOT git add or upload them.")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--from-dir", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    a = p.parse_args()
    stage(a.from_dir, a.output_dir)
