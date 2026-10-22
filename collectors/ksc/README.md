# KSC NagRdu diagnostic collector

This is the **KSC-specific diagnostic runner** adapted from an earlier successful single-host pilot archive. It is not a verbatim copy of the production ZIP and must be tested against one approved endpoint.

Package files as `utility/Run-RamInventory.cmd` and `utility/Collect-RamInventory.ps1` (forward slashes in ZIP). The PowerShell code reads `Win32_PhysicalMemory`; it does not access the internet or require SMB shares. It writes JSON, status and errors to directories advertised by the KSC diagnostic variables `KLACDT_SAVE_SETTINGS` and `KLACDT_SAVE_SETTING`, and keeps a local copy under `%ProgramData%\CorpInventory\RAM`.

It includes manufacturer, part number, slot, bank, capacity and SMBIOS type/speeds but intentionally excludes serial numbers and credentials. Missing SMBIOS fields are reported as `Unknown` rather than being guessed. The output JSON is parsed and strictly validated before SSH forwarding.

The standalone collector in `collectors/windows/` returns JSON by a different mechanism; it is not interchangeable with this ZIP without adaptation.
