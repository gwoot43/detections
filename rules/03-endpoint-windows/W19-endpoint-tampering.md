---
id: W19
name: Endpoint tampering - audit trail destroyed, security stack stopped, or boot integrity turned off
category: endpoint-windows
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1562.001, T1070.004, T1553.006]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, user.name]
  duration: 24h
  missing_fields: do_not_suppress
---

## Why this is high fidelity

Everything below has one property in common: **no administrative task needs it**. `fsutil usn deletejournal`
destroys the record of file changes; `vssadmin delete shadows` destroys the rollback points a responder would use;
`fltmc unload` removes a filter driver; `sc stop csagent` stops the sensor; `bcdedit /set testsigning on` turns off
boot integrity so an unsigned driver will load. Each is a single command, and each is a decision to remove evidence
or capability rather than to do work.

`WE01` covers log clearing (`1102`) and `WE07` covers LSA protection and WDigest. This rule is the rest of the
tamper surface, and it is deliberately one rule: the individual acts are rare, and the value is seeing them together
on one host in one window.

## Query

Run every 15 minutes with a 1-hour lookback.

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 1 hour
  AND event.action IN ("processrollup2", "syntheticprocessrollup2")
  AND host.os.type == "windows"
| EVAL pname = TO_LOWER(COALESCE(process.name, "")),
       cmd = TO_LOWER(COALESCE(process.command_line, ""))
// destroying the record rather than the data
| EVAL destroys_audit = (pname == "fsutil.exe" AND cmd LIKE "*deletejournal*")
                        OR (pname == "wevtutil.exe" AND cmd LIKE "* cl *")
                        OR (pname == "vssadmin.exe" AND cmd LIKE "*delete shadow*")
                        OR (pname == "wmic.exe" AND cmd LIKE "*shadowcopy*" AND cmd LIKE "*delete*"),
// stopping the thing that would have seen it
       stops_defence = (pname IN ("sc.exe", "net.exe", "net1.exe")
                        AND (cmd LIKE "*csagent*" OR cmd LIKE "*csfalconservice*" OR cmd LIKE "*windefend*"
                             OR cmd LIKE "*mpssvc*" OR cmd LIKE "*sysmon*") AND (cmd LIKE "*stop*" OR cmd LIKE "*disabled*"))
                       OR (pname == "fltmc.exe" AND cmd LIKE "*unload*")
                       OR (pname IN ("powershell.exe", "pwsh.exe")
                           AND (cmd LIKE "*set-mppreference*" AND cmd LIKE "*disablerealtimemonitoring*")),
// turning off the protections that make tampering detectable in the first place
       weakens_boot = (pname == "bcdedit.exe" AND (cmd LIKE "*testsigning*" OR cmd LIKE "*nointegritychecks*"
                                                   OR cmd LIKE "*bootmenupolicy legacy*"))
                      OR (pname == "manage-bde.exe" AND (cmd LIKE "*-off*" OR cmd LIKE "*protectors*disable*"))
// collecting rather than tampering - the report-writing half, still worth seeing
       collects = pname LIKE "kape*" OR pname LIKE "velociraptor*" OR pname LIKE "winpmem*"
                  OR cmd LIKE "*ftk imager*" OR cmd LIKE "*magnet ram*"
                  OR (pname == "wevtutil.exe" AND cmd LIKE "* epl *")
                  OR (pname IN ("powershell.exe", "pwsh.exe") AND cmd LIKE "*get-winevent*" AND cmd LIKE "*-path*")
| WHERE destroys_audit OR stops_defence OR weakens_boot OR collects
| EVAL shape = CASE(destroys_audit, "audit_destroyed", stops_defence, "defence_stopped",
                    weakens_boot, "boot_or_encryption_off", "evidence_collected")
| STATS events = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        commands = MV_SLICE(VALUES(process.command_line), 0, 5),
        parents = MV_SLICE(VALUES(process.parent.name), 0, 3),
        users = MV_SLICE(VALUES(user.name), 0, 3)
    BY host.id, host.name, shape, pname
// Baseline: zero for the first three shapes on a healthy estate - no admin task needs them. "evidence_collected"
// is the one with a benign population (the DFIR team), so allowlist that by analyst account rather than by host.
| SORT first_seen DESC
| LIMIT 50
```

## Reading the alert

- **`shape`** is the story. `defence_stopped` on a host that is also running a dump (`W18`) or a pivot (`CS30`) is
  an intrusion, not a test of your tooling.
- **`audit_destroyed` plus `weakens_boot`** in one window is a host being prepared for imaging - the tester is
  taking the disk rather than the data.
- **`evidence_collected`** alone is your DFIR team or a tester writing the report. Read `users` before acting.

## Nearest benign twins

- **The DFIR or IR team** running KAPE, Velociraptor or `wevtutil epl` - allowlist by the analyst's account.
- **A firmware or BitLocker maintenance window** suspending protection - documented, scheduled, and it repeats.
- **An admin clearing shadow copies** because a volume is full - the parent is usually a monitoring script, and it
  happens on one host at a time.

## The general flag you asked for

There is **no single "tampering" field in FDR** that says "something is interfering with the sensor". What exists is
three separate things, and only one of them is general:

1. **The specific commands above** - precise, but only for the techniques someone has written down.
2. **Falcon's own detections and incidents** - *"Sensor tampering"*, *"Security tool disabled"* and similar are
   produced by the platform and live in the detections/incidents API, not in FDR event data. Ingest them as their
   own index and this rule's queue gets the platform's verdict alongside yours.
3. **Absence - the only tool-agnostic flag.** A host that stops emitting events has either been silenced, powered
   off, or lost its network. ES|QL cannot emit an empty time bucket, so this needs a **heartbeat baseline**: a
   lookup or summary index holding each host's normal events-per-hour, compared against the last hour. Build that
   once and it covers every tampering technique, including the ones not listed here.

The probe for (2), to find out what your tenant actually emits before assuming:

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 7 days
| STATS events = COUNT(*) BY event.action
| WHERE event.action LIKE "*tamper*" OR event.action LIKE "*sensor*" OR event.action LIKE "*detection*"
| SORT events DESC
| LIMIT 30
```

Empty means the platform's tamper verdicts are not in your FDR stream and must be pulled from the API instead.

## What it misses

- **Tampering that never touches a command line** - an EDR kill through a driver, a registry edit by a service, a
  WMI call from a script host. `4663` is not collected and there is no registry-write event, so only the absence
  signal (3 above) catches those.
- **Physical tampering** - DMA, a hardware keylogger, a flashed BIOS. No event is produced on the host that is
  compromised. See `pentest_detections/ideas/09-hardware-and-boot-tampering.md`.
- **A tamper that succeeds quietly and is then reverted** - stop the sensor, dump, start it again. The gap is
  minutes long, which is why the heartbeat baseline matters more than any single command rule.

## Test

```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 30 days
  AND event.action == "processrollup2"
  AND host.os.type == "windows"
  AND process.command_line IS NOT NULL
| EVAL pname = TO_LOWER(process.name), cmd = TO_LOWER(process.command_line)
| WHERE (pname == "fsutil.exe" AND cmd LIKE "*deletejournal*")
     OR (pname == "fltmc.exe" AND cmd LIKE "*unload*")
     OR (pname == "bcdedit.exe" AND cmd LIKE "*testsigning*")
| STATS events = COUNT(*) BY host.name, pname, process.parent.name
| SORT events DESC
| LIMIT 30
```

Anything this returns is either a known maintenance script or a finding you already had.
