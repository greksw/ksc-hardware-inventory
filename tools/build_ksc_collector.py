#!/usr/bin/env python3
"""Package two locally reviewed KSC diagnostic collector files, without guessing their content.

The tool REQUIRES the *live* reviewed files passed explicitly by a local operator.
It never packages an entire tree (which could leak archives/results/credentials).
Output contains only `utility/Run-RamInventory.cmd` and
`utility/Collect-RamInventory.ps1`. ZIP files are ignored by .gitignore.
"""
import argparse
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED


def build(cmd: Path, ps1: Path, output: Path) -> None:
    for path in (cmd, ps1):
        if not path.is_file():
            raise FileNotFoundError(path)
        if path.stat().st_size > 256 * 1024:
            raise ValueError(f"Unusually large collector file: {path}")
        if b"\x00" in path.read_bytes():
            raise ValueError(f"Unexpected binary collector file: {path}")
    if output.resolve() in (cmd.resolve(), ps1.resolve()):
        raise ValueError("Output cannot overwrite source")
    output.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(output, mode="w", compression=ZIP_DEFLATED) as z:
        z.write(cmd, arcname="utility/Run-RamInventory.cmd")
        z.write(ps1, arcname="utility/Collect-RamInventory.ps1")
    with ZipFile(output) as z:
        assert set(z.namelist()) == {
            "utility/Run-RamInventory.cmd", "utility/Collect-RamInventory.ps1"
        }
    print(f"Created offline KSC ZIP: {output}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cmd", type=Path, required=True)
    p.add_argument("--ps1", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    build(a.cmd, a.ps1, a.output)
