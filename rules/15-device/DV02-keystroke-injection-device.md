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
- **Audit PNP Activity** (Advanced Audit Policy > Detailed Tracking) set to Success on workstations. Without it, 6416 is never written. If you collect only through Windows Event Forwarding (`logs-windows.forwarded*`), `ClassName` is not in that integration's field list, so the query fails with "Unknown column" until the first 6416 is indexed.
- Hosts are matched on the short host name, lowercased. Windows events use `winlog.computer_name` because, with event forwarding, `host.name` is the collector. Falcon uses `host.name`, which FDR process events only carry when the CrowdStrike integration's "Enrich Host and User Metadata" option (aidmaster) is on. Without it the shells have no host and nothing pairs.

## Query
**Primary (ES|QL with INLINE STATS)**
```esql
FROM logs-system.security*, logs-windows.forwarded*, logs-crowdstrike.fdr-*
| WHERE (event.code == "6416" AND winlog.event_data.ClassName IN ("Keyboard", "HIDClass"))
   OR (event.action == "ProcessRollup2"
       AND TO_LOWER(process.parent.name) == "explorer.exe"
       AND TO_LOWER(process.name) IN ("powershell.exe", "pwsh.exe", "cmd.exe", "wt.exe", "mshta.exe",
                                      "wscript.exe", "cscript.exe", "msiexec.exe", "certutil.exe", "curl.exe"))
| EVAL host_key = TO_LOWER(MV_FIRST(SPLIT(COALESCE(winlog.computer_name, host.name), "."))),
       kb_ts = CASE(event.code == "6416", @timestamp, NULL),
       sh_ts = CASE(event.action == "ProcessRollup2", @timestamp, NULL),
       // device fields from the 6416 side only: on FDR rows device.id is the Falcon sensor ID
       kb_name = CASE(event.code == "6416", device.model.name, NULL),
       kb_id = CASE(event.code == "6416", device.id, NULL),
       sh_user = CASE(event.action == "ProcessRollup2", user.name, NULL)
| INLINE STATS first_kb = MIN(kb_ts) BY host_key
| WHERE first_kb IS NOT NULL
| EVAL gap_s = DATE_DIFF("second", first_kb, @timestamp)
| WHERE kb_ts IS NOT NULL OR (sh_ts IS NOT NULL AND gap_s >= 0 AND gap_s <= 90)
| STATS first_device = MIN(kb_ts), devices = VALUES(kb_name), device_ids = VALUES(kb_id),
        first_shell = MIN(sh_ts), shells = VALUES(process.name), command_lines = VALUES(process.command_line),
        users = VALUES(sh_user), shell_count = COUNT(sh_ts)
    BY host_key
| WHERE shell_count > 0
| EVAL seconds_after_device = DATE_DIFF("second", first_device, first_shell)
| KEEP host_key, first_device, first_shell, seconds_after_device, devices, device_ids, shells, command_lines, users
```

No LogScale version: the rule pairs a new keyboard from Windows Security 6416, which isn't in Falcon, with the shell that follows it, and the FDR half on its own (Explorer starting a shell) is not this detection.

Run every 5 minutes with a 10-minute lookback.

**How the join works.** There are no subqueries, so `INLINE STATS` stamps every row on a host with that host's first new-keyboard time, without collapsing the rows. The shells are then filtered to the 90 seconds after it. If a host sees two new keyboards several minutes apart inside one lookback, only shells within 90 seconds of the first one count. `INLINE STATS` is tech preview and needs a release that has it (9.2 or later at the time of writing). Check your version.

`devices`, `device_ids` and `users` are taken from one side only. FDR also fills `device.id` (with the Falcon sensor ID), and the 6416 `user.name` is the machine account.

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

No LogScale version: same reason as the primary query.

## Suppression
Suppress by `host_key` for 1h. Alerts missing a key field are not suppressed. The 10-minute lookback overlaps the 5-minute interval, so each pair is seen twice.

## Known false positives / exclusions
- **Hot-desking:** a user docks at a new desk (new keyboard) and immediately opens a terminal from Run. Usually one shell with an interactive command line. An injected payload is typically a single long, often encoded or hidden-window command. `rundll32.exe` is left out of the shell list because Explorer starts it for Control Panel, printer and "Safely Remove Hardware" dialogs, which people open right after docking.
- **Build and imaging stations** where technicians plug in keyboards and run scripts. Exclude by `host_key`.
- **Out-of-band management** consoles (iDRAC, iLO, KVM-over-IP) register virtual keyboards on servers. These are usually workstation-only rules. Add `host.os.name` server filtering if your servers have Audit PNP Activity enabled.

## Triage
- Read `command_lines`. A download cradle, an encoded command, or `-w hidden` typed within seconds of plugging in is injection.
- `device_ids` holds the USB VID/PID. Known injection hardware often reuses development-board vendor IDs, but don't rely on it, because clones spoof real keyboard IDs.
- Contain the host with Falcon, find out who was physically at the machine (badge logs, CCTV), and collect the device if it's still there.

## Test
On a lab workstation, plug in a second USB keyboard, press Win+R, type `powershell -c whoami` within 90 seconds.
