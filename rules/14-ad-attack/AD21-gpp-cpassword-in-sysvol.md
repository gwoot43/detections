---
id: AD21
name: Group Policy Preferences password in SYSVOL read or decrypted (cpassword)
category: ad-attack
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1552.006, T1552.001, T1078.002]
data_source: CrowdStrike FDR process events, Windows Security 5140 and 4624
suppression:
  fields: [host.id, user.name]
  duration: 24h
  missing_fields: do_not_suppress
---

## Why this is high fidelity

Group Policy Preferences stored passwords in XML inside SYSVOL, encrypted with a key Microsoft published in 2014
(MS14-025). The files are `Groups.xml`, `Services.xml`, `ScheduledTasks.xml`, `DataSources.xml`, `Drives.xml` and
`Printers.xml`, under `\\<domain>\SYSVOL\<domain>\Policies\{GUID}\Machine\Preferences\`. **Every domain user can read
SYSVOL**, and decryption is one command.

What comes out is usually the local administrator or service account that was pushed to every machine in the
policy's scope - so one file can be the local admin password for the estate. It is old, it is still deployed, and
nothing alerts on it because "SYSVOL is readable by design", which is exactly why it works.

## Query

Run every 30 minutes with a 24-hour lookback.

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 24 hours
  AND event.action IN ("processrollup2", "syntheticprocessrollup2")
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, "")),
       proc = TO_LOWER(COALESCE(process.name, ""))
// the filenames, the field inside them, and the tools that exist only to decrypt them
| WHERE cmd LIKE "*groups.xml*" OR cmd LIKE "*services.xml*" OR cmd LIKE "*scheduledtasks.xml*"
     OR cmd LIKE "*datasources.xml*" OR cmd LIKE "*drives.xml*" OR cmd LIKE "*printers.xml*"
     OR cmd LIKE "*cpassword*"
     OR cmd LIKE "*gpp-decrypt*" OR cmd LIKE "*get-gpppassword*" OR cmd LIKE "*gpp_password*"
| STATS events = COUNT(*), first_seen = MIN(@timestamp),
        commands = MV_SLICE(VALUES(process.command_line), 0, 3),
        parents = MV_SLICE(VALUES(process.parent.name), 0, 3),
        users = MV_SLICE(VALUES(user.name), 0, 3)
    BY host.id, host.name, proc
// Baseline: zero. Nothing in a normal estate names a GPP file on a command line - GPO processing is done by the
// Group Policy service, not by a shell. A single row is the case to read.
| WHERE events >= 1
| SORT first_seen DESC
| LIMIT 50
```

A collector that walks the tree with a library never names a file, so this half catches the shape instead - a
workstation opening SYSVOL far more often than a logon script does:

```esql
FROM logs-yourorg-microsoft-windows*
| WHERE @timestamp >= NOW() - 1 hour
  AND event.code == "5140"
| EVAL share = TO_LOWER(COALESCE(winevt.event_data.share_name, "")),
       acct = TO_LOWER(COALESCE(winevt.event_data.subject_user_name, user.name, "")),
       ip = TO_STRING(winevt.event_data.ip_address)
// machine accounts read policy for every user on the host; this rule is about people
| WHERE share LIKE "*sysvol*" AND NOT acct LIKE "*$"
| STATS opens = COUNT(*), hosts = COUNT_DISTINCT(winlog.computer_name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY acct, ip
// Baseline: a workstation touches SYSVOL once or twice at logon. A sweep walks tens of policy folders in minutes;
// 20 is a starting value - measure the p99 per account before lowering it.
| WHERE opens >= 20
| SORT opens DESC
| LIMIT 50
```

And the half that proves it - SYSVOL read, then a **different** account authenticating from the same address:

```esql
FROM logs-yourorg-microsoft-windows*
| WHERE @timestamp >= NOW() - 30 minutes
  AND event.code IN ("5140", "4624")
| EVAL ip = TO_STRING(COALESCE(winevt.event_data.ip_address, "")),
       share = TO_LOWER(COALESCE(winevt.event_data.share_name, "")),
       tgt = TO_LOWER(COALESCE(winevt.event_data.target_user_name, "")),
       lt = TO_STRING(winevt.event_data.logon_type),
       is_sysvol = event.code == "5140" AND share LIKE "*sysvol*",
       is_logon = event.code == "4624" AND lt == "3"
| WHERE ip != ""
| STATS sysvol_at = MIN(CASE(is_sysvol, @timestamp, NULL)),
        logon_at = MIN(CASE(is_logon, @timestamp, NULL)),
        accounts = MV_SLICE(VALUES(tgt), 0, 5)
    BY ip
// the credential was read, then used, from the same address - which is the pair, not the read
| WHERE sysvol_at IS NOT NULL AND logon_at IS NOT NULL AND logon_at >= sysvol_at
| SORT logon_at DESC
| LIMIT 50
```

## Reading the alert

- **Which file.** `Groups.xml` is the common one (local admin); `Services.xml` carries service account creds, which
  are usually more useful to an attacker because they are domain accounts.
- **Who.** A user who has never touched SYSVOL by hand; a service account is a collector, a person is a tester.
- **What next.** The account in the XML is the one to rotate. Do it before reading the rest of the alert.

## Nearest benign twins

- **`gpupdate` and logon scripts** - they do not name the files on a command line, and their SYSVOL opens come from
  the machine account.
- **Backup and DLP software** crawling SYSVOL, from a server, as a service account.
- **An administrator verifying a GPO** after a change - change-ticketed, and the same person does it every time.

## What it misses

- **A collector using the LDAP/SMB library directly** with no command line, and opening SYSVOL below the 20-open
  threshold.
- **`cpassword` copied to another host before decryption** - the read and the decrypt happen in different places.
- **GPP files outside SYSVOL** (a copy in a file share or a repo) - which is common, and is a data-hygiene problem
  rather than an alert.

## Test

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 30 days
  AND event.action == "processrollup2"
  AND process.command_line IS NOT NULL
| EVAL cmd = TO_LOWER(process.command_line)
| WHERE cmd LIKE "*groups.xml*"
| STATS events = COUNT(*) BY host.name, process.name
| SORT events DESC
| LIMIT 20
```

Run this before enabling: it is both the false-positive check and the answer to "is there still GPP password
material in this estate". If it returns rows, the finding is the files, not the tool.
