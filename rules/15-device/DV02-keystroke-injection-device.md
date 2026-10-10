---
id: DV02
name: New keyboard device followed within seconds by a shell launched from Explorer (keystroke injection, Rubber Ducky, O.MG cable)
category: device
status: todo
severity: high
rank: 1
language: esql
index: logs-system.security*, logs-windows.forwarded*, logs-crowdstrike.fdr-*
mitre: [T1200, T1059.001, T1059.003]
data_source: Windows Security 6416 (new external device, class Keyboard or HIDClass) and CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host_key]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A keystroke-injection device (USB Rubber Ducky, O.MG cable, Flipper Zero in BadUSB mode, a Teensy) enumerates as a new keyboard and types a payload faster than a person can. The usual payload opens Run (Win+R) or Win+X and launches PowerShell or cmd. Either way, Explorer is the parent.

Windows logs 6416 the first time any device instance is seen on a host. A new keyboard followed within 90 seconds by Explorer launching a shell or script host is the injection fingerprint. A person plugging in a new keyboard and opening PowerShell from Run within a minute and a half is rare.

## Prerequisite
- **Audit PNP Activity** (Advanced Audit Policy > Detailed Tracking) set to Success on workstations. Without it, 6416 is never written, and the query fails with "Unknown column" until the first 6416 is indexed.
- Hosts are matched on the short host name, lowercased. Windows events use `winlog.computer_name` because, with event forwarding, `host.name` is the collector. Falcon uses `host.name`.

## Query
**Primary (ES|QL with INLINE STATS)**
```esql
FROM logs-system.security*, logs-windows.forwarded*, logs-crowdstrike.fdr-*
| WHERE (event.code == "6416" AND winlog.event_data.ClassName IN ("Keyboard", "HIDClass"))
   OR (event.action == "ProcessRollup2"
       AND TO_LOWER(process.parent.name) == "explorer.exe"
       AND TO_LOWER(process.name) IN ("powershell.exe", "pwsh.exe", "cmd.exe", "wt.exe", "mshta.exe",
                                      "wscript.exe", "cscript.exe", "rundll32.exe", "msiexec.exe", "certutil.exe", "curl.exe"))
| EVAL host_key = TO_LOWER(MV_FIRST(SPLIT(COALESCE(winlog.computer_name, host.name), "."))),
       kb_ts = CASE(event.code == "6416", @timestamp, NULL),
       sh_ts = CASE(event.action == "ProcessRollup2", @timestamp, NULL)
| INLINE STATS first_kb = MIN(kb_ts) BY host_key
| WHERE first_kb IS NOT NULL
| EVAL gap_s = DATE_DIFF("second", first_kb, @timestamp)
| WHERE kb_ts IS NOT NULL OR (sh_ts IS NOT NULL AND gap_s >= 0 AND gap_s <= 90)
| STATS first_device = MIN(kb_ts), devices = VALUES(device.model.name), device_ids = VALUES(device.id),
        first_shell = MIN(sh_ts), shells = VALUES(process.name), command_lines = VALUES(process.command_line),
        users = VALUES(user.name), shell_count = COUNT(sh_ts)
    BY host_key
| WHERE shell_count > 0
| EVAL seconds_after_device = DATE_DIFF("second", first_device, first_shell)
| KEEP host_key, first_device, first_shell, seconds_after_device, devices, device_ids, shells, command_lines, users
```
Run every 5 minutes with a 10-minute lookback.

**How the join works.** There are no subqueries, so `INLINE STATS` stamps every row on a host with that host's first new-keyboard time, without collapsing the rows. The shells are then filtered to the 90 seconds after it. `INLINE STATS` needs Elastic 9.1+ (tech preview).

**Fallback (no INLINE STATS)**: two-minute buckets. This misses a pair that straddles a bucket edge, but works on 8.x.
```esql
FROM logs-system.security*, logs-windows.forwarded*, logs-crowdstrike.fdr-*
| WHERE (event.code == "6416" AND winlog.event_data.ClassName IN ("Keyboard", "HIDClass"))
   OR (event.action == "ProcessRollup2" AND TO_LOWER(process.parent.name) == "explorer.exe"
       AND TO_LOWER(process.name) IN ("powershell.exe", "pwsh.exe", "cmd.exe", "wt.exe", "mshta.exe", "wscript.exe", "cscript.exe"))
| EVAL host_key = TO_LOWER(MV_FIRST(SPLIT(COALESCE(winlog.computer_name, host.name), "."))),
       kb_ts = CASE(event.code == "6416", @timestamp, NULL),
       sh_ts = CASE(event.action == "ProcessRollup2", @timestamp, NULL)
| STATS first_device = MIN(kb_ts), last_shell = MAX(sh_ts), devices = VALUES(device.model.name),
        command_lines = VALUES(process.command_line)
    BY host_key, window = BUCKET(@timestamp, 2 minutes)
| WHERE first_device IS NOT NULL AND last_shell IS NOT NULL AND last_shell >= first_device
```

## Suppression
Suppress by `host_key` for 1h. Alerts missing a key field are not suppressed. The 10-minute lookback overlaps the 5-minute interval, so each pair is seen twice.

## Known false positives / exclusions
- **Hot-desking:** a user docks at a new desk (new keyboard) and immediately opens a terminal from Run. Usually one shell with an interactive command line. An injected payload is typically a single long, often encoded or hidden-window command.
- **Build and imaging stations** where technicians plug in keyboards and run scripts. Exclude by `host_key`.
- **Out-of-band management** consoles (iDRAC, iLO, KVM-over-IP) register virtual keyboards on servers. These are usually workstation-only rules. Add `host.os.name` server filtering if your servers have Audit PNP Activity enabled.

## Triage
- Read `command_lines`. A download cradle, an encoded command, or `-w hidden` typed within seconds of plugging in is injection.
- `device_ids` holds the USB VID/PID. Known injection hardware often reuses development-board vendor IDs, but don't rely on it, because clones spoof real keyboard IDs.
- Contain the host with Falcon, find out who was physically at the machine (badge logs, CCTV), and collect the device if it's still there.

## Test
On a lab workstation, plug in a second USB keyboard, press Win+R, type `powershell -c whoami` within 90 seconds.
