# Security and publication boundaries

1. **Never upload** live KSC SDK packages, CA or server certificates, private/public SSH keys, admin passwords, KSC gateway tokens, authentication headers, private hosts CSV files, ZIP execution results, SQLite databases, or SSH known_hosts.
2. Use separate identities: restricted KSC Open API principal and forced-command SSH import user. A Windows/domain administrator is not interchangeable with KSC API administrator.
3. TLS validation MUST be on for both `KlAkAdmServer.Create` and `CreateGateway`. The certificate presented through a localhost tunnel must match the URL hostname. Pin/trust a verified issuer; confirm fingerprint out of band; re-check on KSC certificate rotation.
4. For KSC remote execution (`NagRdu.ExecuteFileAsync`), restrict accessible hosts and verify exact identity/host GUID before uploading. Default to **one pilot**; no uncontrolled fleet-wide scheduling.
5. An accepted async action is not a successful execution. Check `bFinalized` and `bSuccededFinalized`, validate retrieved JSON and record the action ID in private logs.
6. The SSH receiver must have `restrict,command="..."` in authorized_keys and an exact `sudoers` no-args rule. The importer and configuration must be writable only by root.
7. The audit script catches common leaks only. Always inspect the **complete git diff and history** before public push. A GitHub public repository and its commit history are effectively permanent.
8. Report security issues privately to the repository maintainer; do not include internal topology or keys in public issues.
9. `ksc_inventory.ksc_runner` defaults to offline `preflight`. The live `probe` reads endpoint state and the live `collect` requires exact ComputerName confirmation, approved GUID and matching collector SHA256. Do not run `collect` on a fleet without a new review and separate scheduling layer.
10. Once issued, a KSC async action may continue after client timeout or network interruption. **Never retry automatically** without reconciling action state using its Action ID.
11. Do not enable SSH agent forwarding or accept unverified host keys. `--send` may import a validated report only after an explicitly approved collect.
