#!/usr/bin/env python3
"""One-host KSC collection; explicit confirmation and collector fingerprint required."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ksc_inventory.ksc_runner import main

if any(arg == '--mode' or arg.startswith('--mode=') for arg in sys.argv[1:]):
    sys.exit('ERROR: ram_pilot.py only permits --mode collect')
sys.exit(main(['--mode', 'collect', *sys.argv[1:]]))
