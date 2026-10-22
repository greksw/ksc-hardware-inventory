#!/usr/bin/env python3
"""Read-only live KSC Gateway/NagRdu access check (requires vendor SDK)."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ksc_inventory.ksc_runner import main

if any(arg == '--mode' or arg.startswith('--mode=') for arg in sys.argv[1:]):
    sys.exit('ERROR: gateway_probe.py only permits --mode probe')
sys.exit(main(['--mode', 'probe', *sys.argv[1:]]))
