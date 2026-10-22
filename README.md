# KSC Hardware Inventory

A single-host, security-conscious RAM inventory toolkit for **Kaspersky Security Center 15.1 Open API**, Python and Windows PowerShell. It is based on an actual successful one-machine KSC → Network Agent → RAM JSON → restricted SSH → Inventory API → SQLite pilot. The **refactored runner and adapted KSC collector were validated on one approved Windows workstation against live KSC 15.1 on 2026-10-22**: TLS-verified gateway probe, remote collection, result ZIP/JSON validation and separate restricted-SSH import with a new SQLite report. The 27 autonomous tests mock SDK interactions; fleet-wide operation has not been validated.

**[Русская инструкция](README.ru.md)** covers setup and pilot execution in detail. See also the [source-code review notes](REVIEW_NOTES.ru.md).

## Contents

- `ksc_inventory/ksc_runner.py`: KlAkOAPI single-host runner (`preflight`, `probe`, `collect`). Imports the proprietary SDK only for live calls.
- `collectors/ksc/utility/`: CMD + PowerShell for KSC remote diagnostics; captures per-DIMM metadata and places reports in KSC result folders.
- `collectors/windows/Collect-RamInventory.ps1`: independently published standalone read-only collector from [PR #50](https://github.com/greksw/notes.shandrov.ru/pull/50), with local/optional restricted SMB output. This is **not** the KSC diagnostic collector.
- `ksc_inventory/result.py`: safe ZIP/JSON validation with computer-name, timestamp and RAM checks.
- `ksc_inventory/import_result.py`: validation and optional restricted SSH ingest; no remote command and no root login.
- `scripts/gateway_probe.py`, `scripts/ram_pilot.py`, `scripts/import_result.py`: familiar entry point wrappers; `python -m ...` is recommended.
- `tools/`: verified-content ZIP builder, offline safety audit, optional private source staging.
- `tests/`: mocked SDK sequencing and offline safety regressions.

## Threat model

The operator must approve one physical endpoint by **exact FQDN, reported computer name and KSC host GUID** before any remote executable is uploaded. Collection additionally requires `--confirm-computer` and the approved ZIP SHA256. The default `preflight` has no network access, `probe` reads agent state but does not execute a collector, and `collect` runs exactly one KSC async action. The action may continue on the agent after client timeout; never retry blindly.

KSC requires sensitive Connectivities/Common permissions, so scope the dedicated API user carefully. The SSH importer uses a separate Ed25519 key, verified `known_hosts`, and receiver-side `restrict,command=...` plus a narrow `sudoers` rule; the Inventory API key never leaves the receiver. Never bundle or publish the proprietary Kaspersky SDK, private certs, SSH keys, real endpoint identifiers or RAM reports.

## Offline verification

```bash
python3 -m unittest discover -s tests -v
python3 tools/audit_publication.py
```

## Live operator workflow

The proprietary SDK must be provided by your KSC environment, for example through `PYTHONPATH`. Prepare a CA issuer PEM independently authenticated against the KSC certificate; use a DNS name matching its SAN even when tunneled through loopback.

```bash
export PYTHONPATH="$PWD:/path/to/KlAkOAPI-SDK-DIRECTORY"
export KSC_URL='https://ksc.example.test:13299'
export KSC_CA_FILE='/path/to/ksc-issuer-ca.pem'
export KSC_USER='ksc-inventory-user'
export KSC_TARGET_FQDN='pc-demo-01.example.test'
export KSC_EXPECTED_COMPUTER='PC-DEMO-01'
export KSC_EXPECTED_GUID='REPLACE_WITH_APPROVED_GUID'

python3 tools/build_ksc_collector.py \
  --cmd collectors/ksc/utility/Run-RamInventory.cmd \
  --ps1 collectors/ksc/utility/Collect-RamInventory.ps1 \
  --output /path/to/approved-collector.zip

sha256sum /path/to/approved-collector.zip
python -m ksc_inventory.ksc_runner --mode preflight --collector /path/to/approved-collector.zip
python -m ksc_inventory.ksc_runner --mode probe
# Live remote execution on approved single host only:
python -m ksc_inventory.ksc_runner --mode collect \
  --collector /path/to/approved-collector.zip \
  --collector-sha256 REPLACE_WITH_SHA256 \
  --confirm-computer "$KSC_EXPECTED_COMPUTER"
```

The runner asks for the KSC API password interactively unless supplied via a mode-0600 `--password-file` stored **outside Git**. By default the downloaded validated ZIP is **not** forwarded to the receiving Inventory API. To send it later, use the offline/import CLI with explicit `--send` after verifying the SSH forced command, or add `--send`, `--ssh-destination`, and `--identity` to a controlled `collect` run.

## Security and publication

Source code is adapted and anonymized from a real pilot and an earlier independently published Windows collector. GitHub CI exercises Python paths with fake SDK classes; **independent live testing has also passed for one workstation**, as documented in [VALIDATION.ru.md](VALIDATION.ru.md). Neither evidence supports an unreviewed fleet-wide rollout. Repeat single-host verification after SDK, collector, KSC permissions or TLS certificate changes.

```bash
# In a NEW clean project directory, after validating all staged content:
python3 -m unittest discover -s tests -v
python3 tools/audit_publication.py
git init -b main
git add -A
git diff --cached --check
git diff --cached --stat
git diff --cached  # human review, including docs/tests
# After review and live pilot, publish explicitly:
git commit -m 'feat: initial KSC hardware inventory toolkit'
gh repo create greksw/ksc-hardware-inventory --public --source=. --remote=origin --push
```

Do **not** initialize a repo inside the operational `ksc-inventory` directory or copy its vendor SDK/certificates/results. See [SECURITY.md](SECURITY.md).

## Related writeups

- [Individual RAM module inventory via KSC](https://notes.shandrov.ru/ru/notes/monitoring/ksc-openapi-ram-module-inventory/)
- [KSC 1184 authorization diagnostics](https://notes.shandrov.ru/ru/notes/monitoring/ksc-openapi-nagrdu-1184-rbac/)
- [Verified TLS and restricted SSH ingest](https://notes.shandrov.ru/ru/notes/monitoring/ksc-openapi-verified-tls-inventory-ingest/)

MIT License for this project code and authored collectors. Kaspersky SDK remains separately licensed.
