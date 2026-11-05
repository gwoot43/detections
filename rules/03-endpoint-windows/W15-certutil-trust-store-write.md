---
id: W15
name: certutil writing a trust-granting store
category: endpoint-windows
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1140, T1553.002, T1553.004]
data_source: CrowdStrike FDR / Windows Security events
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
`certutil` is a signed Windows binary, so app-control and signature policy let it run. `-addstore` and `-importpfx`
let it write to the certificate stores, and the stores that matter are the ones that decide trust rather than the
ones that hold a user's identity:

- **`root` / `authroot`** - forge a trusted CA, and every certificate that chains to it is trusted.
- **`trustedpublisher`** - forge code-signing trust, which bypasses signature policy without a CA.
- **`ca`** - plant a rogue intermediate.
- `my` / `personal` is deliberately out of scope: it grants no trust over anything else.

The anchor is the **verb**, not the binary name, so a renamed or copied `certutil` still trips it, and the verb is
corroborated by one of four things: the certificate came from a user-writable path, the binary did, a script host
or Office or a browser asked for it, or the binary's original name says `certutil.exe` while its path does not.

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 15 minutes
  AND event.action == "processrollup2"
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, "")),
       exe = TO_LOWER(COALESCE(process.executable, "")),
// parent.executable is null on some pipelines, and an exclusion against a null field excludes nothing
       parent = TO_LOWER(COALESCE(process.parent.executable, process.parent.name, "")),
// store matched as a space-bounded token, so a filename like my-root.pfx cannot set it
       finding = CASE(cmd LIKE "* trustedpublisher *", "forged_code_signing_trust",
                      cmd LIKE "* authroot *" OR cmd LIKE "* root *" OR cmd LIKE "* ca *", "rogue_ca_trust",
                      ""),
// the binary, or the certificate it installs, came from somewhere a user can write
       writable = exe RLIKE """.*\\(users|temp|appdata|programdata|downloads)\\.*"""
                  OR cmd RLIKE """.*\\(users|temp|appdata|programdata|downloads)\\.*(cer|pfx|p7b).*""",
// a script host, Office, a browser or an interpreter asked for it - not an installer
       from_payload = parent RLIKE """.*(powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|wmiprvse|winword|excel|outlook|chrome|msedge|firefox|python|node|java).*""",
// the verb survives a rename, the name does not
       renamed = TO_LOWER(COALESCE(process.pe.original_file_name, "")) == "certutil.exe"
                 AND NOT exe LIKE """*\\certutil.exe"""
// the verb has to be there at all
| WHERE (cmd LIKE "*addstore*" OR cmd LIKE "*importpfx*") AND finding != ""
// signed agents that legitimately plant a root, as entity pairs rather than command strings
  AND NOT (parent LIKE """*\\taniumcx.exe""" OR parent LIKE "*system_update_*")
// a forged code-signing trust always alerts; a CA install needs one reason to be suspicious
  AND (finding == "forged_code_signing_trust" OR writable OR from_payload OR renamed)
| KEEP @timestamp, host.name, user.name, finding, writable, from_payload, renamed,
       process.executable, process.parent.executable, process.command_line
| SORT @timestamp DESC
| LIMIT 100
```

Deploy every 5 minutes over the last 15. Suppress by `host.id` + `finding` for 24h.

## Reading the alert
- **`finding`** splits the response: `forged_code_signing_trust` is a signature bypass with no CA needed, so it is
  an immediate isolation; `rogue_ca_trust` means every certificate chaining to the planted CA is now trusted,
  which is a trust-store rebuild rather than a file cleanup.
- **`writable`** is the strongest corroborator when true of the *certificate*: `-addstore root C:\Users\x\Downloads\evil.cer`
  is a payload, while `-addstore root "C:\Program Files\Vendor\ca.cer"` is a product.
- **`from_payload`** names who asked. `msiexec.exe` or a signed updater is a product doing its job;
  `powershell.exe`, `winword.exe` or a browser is not.
- **`renamed`** is the rename test: the verb survives, the file name does not. It is enrichment — the rule fires
  on the verb regardless — and it is often the difference between a curious admin and tooling.

## Nearest benign twins
- **VPN, proxy and TLS-inspection vendors** install their own root CA: Zscaler, Netskope, Palo Alto, Citrix,
  Fortinet. `store = root` from `msiexec.exe` with a certificate under `Program Files` is exactly that, and the
  corroborator gate is what removes it — not a vendor list.
- **Enterprise agents** that maintain a trust anchor on a schedule: Tanium's `trustedpublisher` install and
  Lenovo's `system_update_*` intermediate are the two entity pairs above; add your own by reading the first
  week's alerts rather than guessing.
- **IT provisioning a CA for a lab or an internal PKI.** Ticketed, and it comes from an admin console under a
  Tier-0 account rather than from a script host.

## What it misses
- **The download**, which is the other half of the same LOLBin: `certutil -urlcache -split -f http://… file` is
  how the certificate gets onto the host in the first place. Not in this rule — `urlcache` has almost no
  legitimate use in a managed estate, so it is worth its own branch or rule.
- **Private-key theft**: `-exportPFX`, `-backupKey`, `-ExportCert` read keys out rather than trusting something in.
  Different finding, different response.
- **PowerShell's own path** — `Import-Certificate -CertStoreLocation Cert:\LocalMachine\Root` writes the same
  store without `certutil` at all. This rule is silent on it.
- **A write through a management tool** (SCCM, Intune, a PKI agent) that legitimately distributes roots. Those are
  entity pairs, and they will appear in the first week.
- **`-importpfx` without a store name**, which lands in `my`: correct to ignore for trust, and it does fall out on
  the `finding` test rather than by accident.

## Probe before enabling
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 24 hours
  AND event.action == "processrollup2"
| STATS events = COUNT(*),
        with_executable = COUNT(*) WHERE process.executable IS NOT NULL,
        with_parent = COUNT(*) WHERE process.parent.executable IS NOT NULL,
        with_orig_name = COUNT(*) WHERE process.pe.original_file_name IS NOT NULL
```
`with_parent` at zero means the parent fallback is doing all the work — fine, but the entity-pair exclusions then
key on `process.parent.name` instead. `with_orig_name` at zero means `renamed` is permanently false: the rule still
fires on the verb, but the rename corroborator is silently gone.

## References
- MITRE T1553.004 (install root certificate), T1553.002 (code signing), T1140-adjacent LOLBin abuse
- `rules/14-ad-attack/CERTIPY-03-cert-pipe-on-ca.md`, `AD06`/`AD14` - the CA side: where a rogue certificate is issued, rather than trusted
- `docs/ESQL-CONVENTIONS.md` - triple-quoted strings for Windows paths, `RLIKE` without anchors
