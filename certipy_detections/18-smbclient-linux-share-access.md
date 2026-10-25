---
id: LATMOV-05
name: smbclient on Linux reaching an admin share or pulling files in bulk (Samba smbclient, Impacket smbclient.py)
language: cql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1021.002, T1039, T1570]
data_source: CrowdStrike FDR ProcessRollup2 (Linux)
suppression:
  fields: [host.id, user.name]
  duration: 6h
  missing_fields: do_not_suppress
---
**Catches:** `smbclient` on a Linux host used the way an operator uses it - reaching an admin share, or pulling files recursively/in bulk. Samba's `smbclient` and Impacket's `smbclient.py` are the common Linux SMB clients for share access and file theft from a foothold.

`smbclient` also runs in legitimate backup and integration scripts, so the anchor (the tool) is paired with the behaviour that routine scripts don't do:
- **an admin share** - `//host/C$` or `//host/ADMIN$`. Scripts copy from named data shares, not the admin shares.
- **a recursive or scripted bulk pull** - `recurse`, `mget`, `mask`, `prompt off`. That is looting a share, not fetching one known file.

A single `smbclient` fetch of one file from a data share is left out on purpose - it's indistinguishable from a backup job here, and mass share access is better seen target-side by 10.

Run every 10 minutes over the last 15.
```logscale
#event_simpleName=ProcessRollup2 event_platform=Lin
// Samba smbclient, or Impacket's smbclient.py
| ImageFileName=/\/smbclient$/ OR CommandLine=/\bsmbclient\.py\b/
| cmd := lower(CommandLine)
// high-fidelity use: an admin share (C$/ADMIN$), or a recursive/scripted bulk pull
// Deliberately no * branch: this case is the filter.
| case {
    cmd=/\/\/[^\/\s]+\/(?:c|admin)\$/ | behaviour := "admin share" ;
    cmd=/(?:recurse|\bmget\b|\bmask=|prompt\s+off)/ | behaviour := "bulk pull" ;
  }
| groupBy([aid, UserName], function=[collect([ComputerName, CommandLine, ParentBaseFileName, behaviour], limit=50), count(as=runs), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)], limit=max)
| match(file="aid_master_main.csv", field=aid, include=[ComputerName], strict=false)
| select([ComputerName, UserName, runs, behaviour, CommandLine, ParentBaseFileName, first_seen, last_seen])
```
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Samba smbclient, or Impacket's smbclient.py, on a Linux host
| WHERE event.action == "processrollup2" AND host.os.type != "windows"
| EVAL cmd = TO_LOWER(process.command_line)
// the tool: smbclient by name, or smbclient.py on the command line (substring match, so a wildcard both sides)
| WHERE (process.name == "smbclient" OR cmd LIKE "*smbclient.py*")
// high-fidelity use: an admin share (C$/ADMIN$), or a recursive/scripted bulk pull
  AND (cmd LIKE "*/c$*" OR cmd LIKE "*/admin$*" OR cmd LIKE "*recurse*" OR cmd LIKE "*mget*" OR cmd LIKE "*mask=*" OR cmd LIKE "*prompt off*")
| EVAL behaviour = CASE(cmd LIKE "*/c$*" OR cmd LIKE "*/admin$*", "admin share", "bulk pull")
| STATS runs = COUNT(*), command_lines = MV_SLICE(VALUES(process.command_line), 0, 49),
        parents = VALUES(data.ParentBaseFileName), behaviour = VALUES(behaviour),
        host.name = VALUES(host.name), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.id, user.name
```
Suppress by host and user for 6h.

## What it catches and what it doesn't
- **Caught:** `smbclient`/`smbclient.py` on Linux reaching an admin share or pulling files recursively - the foothold-to-file-theft pattern.
- **Not caught here:** a single file fetch from a named data share (too close to a backup job - left out on purpose). Mass share access across many hosts is detection 10, target-side.
- **Not caught here:** `smbclient.py` run on **Windows** - that's detection 17 (a user process speaking SMB).
- **Not caught here:** mounting a share with `mount.cifs`/`gvfs` (that's the kernel, not smbclient) - a different Linux SMB path.

## Before turning it on
- Confirm `smbclient` appears as `ImageFileName=.../smbclient` and that `CommandLine` is populated on your Linux ProcessRollup2 events.
- Run it over a week and exclude the backup and integration accounts that legitimately pull in bulk, as host + user pairs - not by muting a behaviour.

## When it fires
`CommandLine` shows the share and the operation, `ParentBaseFileName` what launched it (a shell from a web worker or an unexpected parent is the foothold - see 13), `UserName` the account. A web or service account running `smbclient` against an admin share is an operator looting shares from a foothold. Check what the same host reached over SMB (17 doesn't apply on Linux, but the raw 445 connections are in Falcon) and whether the pulled files left the host.
