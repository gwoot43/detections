---
id: W18
name: Credential hive dumped - SAM, SYSTEM or SECURITY written out by reg, esentutl, a shadow copy or lsadump
category: endpoint-windows
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1003.002, T1003.003, T1003.004]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, user.name]
  duration: 24h
  missing_fields: do_not_suppress
---

## Why this is high fidelity

Three registry hives hold everything an attacker needs from a host they own: **SAM** (local account hashes),
**SYSTEM** (the boot key that decrypts them) and **SECURITY** (LSA secrets - service account passwords, the machine
account password, DPAPI keys). They are dumped by writing them out with `reg save`, by copying the files with
`esentutl` (they are ESE databases), by creating a volume shadow copy and reading them out of it, or by a tool
calling `lsadump::` directly.

**Defender for Endpoint already detects the tool** - *"Potential credential dumping"*, the Mimikatz family - and it
has the file-read visibility this estate lacks (`4663` is not collected). So this rule is not primary coverage. It
exists for three cases Defender does not cover:

1. **Hosts with a sick, passive or excluded Defender agent** - which is where a dump actually happens.
2. **One queue** - the dump correlates with the proxy, the scan and the admin grant in the same alert stream.
3. **The destination** - Defender alerts on the tool; the useful part is often *where the hive went*. A hive saved
   into `%TEMP%` or `Users\Public` is being carried off; one saved to a backup volume is a backup job.

`WE09` covers the NTDS and shadow-copy shapes on domain controllers. This is the host-agnostic hive rule.

## Query

Run every 5 minutes with a 15-minute lookback - a shadow copy and its copy-out are minutes apart at most.

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 15 minutes
  AND event.action IN ("processrollup2", "syntheticprocessrollup2")
  AND host.os.type == "windows"
| EVAL pname = TO_LOWER(COALESCE(process.name, "")),
       cmd = TO_LOWER(COALESCE(process.command_line, ""))
// The three hives, in both spellings: the registry path (reg) and the file path (esentutl, copy).
// Triple quotes because a backslash is processed twice otherwise and the pattern never matches.
| EVAL hive = cmd LIKE """*\\config\\sam*""" OR cmd LIKE """*\\config\\system*""" OR cmd LIKE """*\\config\\security*"""
              OR cmd LIKE """*hklm\\sam*""" OR cmd LIKE """*hklm\\system*""" OR cmd LIKE """*hklm\\security*"""
// reg save writes the hive; reg export writes its values as text, which is enough for secretsdump-style parsing
| EVAL hive_save = pname == "reg.exe" AND (cmd LIKE "*save*" OR cmd LIKE "*export*") AND hive,
// esentutl is not only for ntds.dit - it copies any ESE database, and SAM/SECURITY are ESE databases
       esent_hive = pname == "esentutl.exe" AND hive,
       shadow = (pname == "vssadmin.exe" AND cmd LIKE "*create shadow*")
                OR (pname == "diskshadow.exe" AND (cmd LIKE "*create*" OR cmd LIKE "*expose*"))
                OR (pname == "wmic.exe" AND cmd LIKE "*shadowcopy*" AND cmd LIKE "*call create*"),
       copy_out = cmd LIKE "*harddiskvolumeshadowcopy*",
       lsadump = cmd LIKE "*lsadump::sam*" OR cmd LIKE "*lsadump::secrets*" OR cmd LIKE "*lsadump::lsa*"
                 OR cmd LIKE "*lsadump::cache*"
| WHERE hive_save OR esent_hive OR shadow OR copy_out OR lsadump
// the destination is the tell: user-writable paths mean the hive is leaving the host
| EVAL to_temp = hive_save AND (cmd LIKE """*\\temp\\*""" OR cmd LIKE """*\\users\\*"""
                               OR cmd LIKE """*\\programdata\\*""" OR cmd LIKE """*\\perflogs\\*""")
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        commands = MV_SLICE(VALUES(process.command_line), 0, 4),
        parents = MV_SLICE(VALUES(process.parent.name), 0, 3),
        users = MV_SLICE(VALUES(user.name), 0, 3)
    BY host.id, host.name, pname, to_temp
// Baseline: backup products run shadow copies and hive saves on a schedule, from a service account, to a backup
// volume. Anything from a human account, or to a user-writable path, is the case - there is no threshold to tune,
// the destination and the account do the work.
| SORT first_seen DESC
| LIMIT 50
```

## Reading the alert

- **`to_temp` true** is the strongest single field: `reg save hklm\sam c:\users\public\s.save` is not
  administration.
- **`pname`** tells you the method. `reg.exe` is hands-on; `esentutl` is someone who knows the files are ESE;
  `wmic shadowcopy` is a script.
- **`users`** - a service account running this is a backup product or an attacker using one. Check the destination
  before deciding.

## Nearest benign twins

- **Backup products** (Veeam, Commvault, Windows Server Backup) - shadow copies and hive saves, scheduled, service
  account, backup volume.
- **A DC promotion or a host rebuild** - documented, and it runs on a host being built rather than a running one.
- **An administrator exporting a hive to inspect a setting** - rare, one hive, and to a working folder rather than
  `%TEMP%`.

## What it misses

- **The API path.** A tool opening `\\.\C:\Windows\System32\config\SAM` directly, or mimikatz run from a
  loaded DLL, leaves a process start with no arguments. `4663` is not collected, so the read is invisible - that
  case belongs to Defender and to Falcon's own IOAs (`CS08`).
- **A hive copied to a share** rather than written locally - the write is local, so it still matches, but the copy
  that matters happens over SMB afterwards.
- **Volume shadow copies created by `ntdsutil`** - that is `WE09`'s shape on a DC.

## Test

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 30 days
  AND event.action == "processrollup2"
  AND host.os.type == "windows"
  AND process.command_line IS NOT NULL
| EVAL pname = TO_LOWER(process.name), cmd = TO_LOWER(process.command_line)
| WHERE (pname == "reg.exe" AND cmd LIKE "*save*")
     OR pname IN ("vssadmin.exe", "diskshadow.exe", "esentutl.exe")
| STATS events = COUNT(*) BY host.name, pname, process.parent.name
| SORT events DESC
| LIMIT 30
```

The parents in this list are your backup products. Everything else is worth reading before the rule is enabled.
