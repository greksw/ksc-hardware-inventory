# Windows RAM collector

This is the same owner-published PowerShell 5.1 read-only collector from
[`greksw/notes.shandrov.ru` PR #50](https://github.com/greksw/notes.shandrov.ru/pull/50).

It collects RAM slots, banks, manufacturers, part numbers, capacities,
SMBIOS memory types and nominal/configured speeds, then writes local JSON.
An optional SMB drop may be supplied but is **disabled by default**.

**Not a KSC NagRdu ZIP payload.** The separate adapted KSC diagnostic collector
in `collectors/ksc/utility/` writes results to the KSC-designated save directory.
The two collectors serve different delivery workflows.
