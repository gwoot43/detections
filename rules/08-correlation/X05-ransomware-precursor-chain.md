---
id: X05
name: Ransomware precursor chain on one host
category: correlation
status: todo
severity: critical
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1486, T1490, T1685, T1489]
data_source: CrowdStrike FDR (W05/W06/CS01) on the same host in a short window
suppression:
  fields: [host.id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Ransomware detonation is a recognisable sequence: disable defenses (W05 / CS01 BYOVD), then destroy backups (W06), then encrypt (mass file writes). Any two of these on one host within thirty minutes is a detonation in progress, and catching it between defense-disable and encryption is the difference between one host and the whole estate.

## Query
```esql
FROM logs-crowdstrike.fdr-*
| WHERE @timestamp > NOW() - 30 minutes AND host.os.type == "windows"
  AND event.action IN ("ProcessRollup2", "DriverLoad")
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, "")),
       pname = TO_LOWER(COALESCE(process.name, "")),
       drv = TO_LOWER(COALESCE(dll.path, ""))
| EVAL stage = CASE(
      // Defender switched off (not back on), Defender or Falcon service stopped, or a driver loaded from a temp folder (BYOVD)
      (cmd LIKE "*set-mppreference*-disable*" AND NOT cmd LIKE "*$false*")
        OR (pname IN ("sc.exe", "net.exe", "net1.exe") AND (cmd LIKE "*stop*" OR cmd LIKE "*disabled*")
            AND (cmd LIKE "*windefend*" OR cmd LIKE "* sense*" OR cmd LIKE "*wdnissvc*" OR cmd LIKE "*csfalcon*"))
        OR (event.action == "DriverLoad" AND drv LIKE """*\\temp\\*"""), "defense_disable",
      (pname == "vssadmin.exe" AND (cmd LIKE "*delete shadows*" OR cmd LIKE "*resize shadowstorage*"))
        OR (pname == "wmic.exe" AND cmd LIKE "*shadowcopy*delete*")
        OR (pname == "wbadmin.exe" AND cmd LIKE "*delete*")
        OR (pname == "bcdedit.exe" AND (cmd LIKE "*recoveryenabled no*" OR cmd LIKE "*ignoreallfailures*")), "backup_destroy",
      pname == "cipher.exe" AND cmd LIKE "*/w*", "impact_prep",
      NULL)
| WHERE stage IS NOT NULL
| STATS stages = COUNT_DISTINCT(stage), which = VALUES(stage), cmds = VALUES(process.command_line), drivers = VALUES(dll.path),
        host_names = VALUES(host.name), users = VALUES(user.name), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.id
| WHERE stages >= 2
```
Run every 10 minutes. The 30-minute lookback is the window, so two stages anywhere in it pair up. There is no `BUCKET`, so a chain is never split across a bucket edge.

Field notes:
- The rule groups on `host.id` (the Falcon agent ID), which every FDR event carries. `host.name` only exists when the integration's "Enrich Host and User Metadata" option is on, so it's reported but not used as the key.
- A `DriverLoad` event puts the driver path in `dll.path`. `file.path` is empty on driver events.
- `"*$false*"` drops `Set-MpPreference -Disable... $false`, which turns protection back on.

## Suppression
Suppress by `host.id` for 1h. Alerts missing a key field are not suppressed. Aggregating rule. Every new host still alerts.

## Known false positives / exclusions
- A backup server where the backup product prunes shadow copies while an admin changes Defender settings. Exclude those servers by `host.id`.
- Hardware utilities (CPU-Z, HWiNFO and similar) unpack a signed driver to `%TEMP%` and load it. That alone is one stage. It only alerts together with a second stage.

## Triage
- Isolate immediately and sweep the fleet for the same stages: ransomware runs in parallel across hosts. Pull the encryptor binary and block its hash fleet-wide.

## Test
In an isolated lab VM, delete shadow copies and turn off Defender real-time monitoring within 30 minutes.
