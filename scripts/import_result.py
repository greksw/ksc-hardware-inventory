#!/usr/bin/env python3
"""Offline ZIP validation and optional restricted SSH import."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ksc_inventory.import_result import main

if __name__ == '__main__':
    raise SystemExit(main())
