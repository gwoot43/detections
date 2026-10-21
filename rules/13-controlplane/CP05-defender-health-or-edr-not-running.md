---
id: CP05
name: Microsoft Defender health degraded, or the Defender AV or MDE sensor service stopped and stayed down
category: controlplane
status: todo
language: esql
index: logs-windows.windows_defender-*, logs-system.system-*
mitre: [T1685, T1489]
data_source: Defender Operational channel (5008, 5101, 2004, 3002, 1151 health report) and System channel Service Control Manager (7036, 7031, 7034)
suppression:
  fields: [host.name, component, problem]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Where Defender runs beside CrowdStrike, its health is a second coverage signal. This rule fires only when protection is actually broken:
- **The engine crashed** (5008).
- **The platform has expired** (5101).
- **Signatures failed to load and were rolled back** (2004).
- **A real-time protection feature failed** (3002).
- **Signatures are a week or more old**, read from the periodic 1151 health report.
- **The Defender AV or Defender for Endpoint (Sense) service crashed**, or **was stopped and hadn't restarted 15 minutes later**.

Settings being switched off (real-time protection off, exclusions added, tamper attempts) live in **CP06**. Detections and blocks live in **WE10**.

**What changed from the first version, and why:**
- **1150 and 1151 were removed as alert triggers.** They are Defender's "running and healthy" heartbeat and its periodic health report. As triggers they would have alerted on every host twice a day. 1151 is now parsed for signature age instead.
- **The service branch matches display names.** 7036 records the service *display name* in `param1` (for example "Windows Defender Advanced Threat Protection Service"), not `windefend` or `sense`, so the old match could never hit.
- **Service stops must persist.** Monthly platform updates restart WinDefend, so a stop only counts when no "running" event follows it.

## Prerequisite
- Turn on the **Windows Defender** stream in the Elastic Windows integration (it ships disabled), and collect the System channel with the System integration.
- Rule interval 15 minutes, lookback 1 hour. The stop-and-stayed-down check needs the lookback to cover the 15-minute grace period.

## Query
```esql
FROM logs-windows.windows_defender-*, logs-system.system-*
| WHERE (winlog.channel == "Microsoft-Windows-Windows Defender/Operational"
         AND event.code IN ("5008", "5101", "2004", "3002", "1151"))
   OR (winlog.channel == "System" AND winlog.provider_name == "Service Control Manager"
       AND event.code IN ("7036", "7031", "7034"))
| EVAL svc = TO_LOWER(COALESCE(winlog.event_data.param1, "")),
       state = TO_LOWER(COALESCE(winlog.event_data.param2, "")),
       msg = TO_LOWER(COALESCE(message, ""))
| WHERE winlog.channel != "System"
   OR svc LIKE "*defender antivirus service*"
   OR svc LIKE "*defender advanced threat protection*"
   OR svc LIKE "*defender for endpoint*"
| GROK msg """antivirus security intelligence age:[ \t]*%{INT:sig_age}"""
| EVAL component = CASE(winlog.channel == "System", svc, "defender health"),
       problem = CASE(
         event.code == "5008", "engine terminated unexpectedly",
         event.code == "5101", "antimalware platform expired",
         event.code == "2004", "signatures failed to load, reverted",
         event.code == "3002", "real-time protection feature failed",
         event.code == "1151" AND TO_INTEGER(sig_age) >= 7 AND TO_INTEGER(sig_age) < 10000, "signatures 7+ days old",
         event.code IN ("7031", "7034"), "service crashed",
         NULL),
       stop_ts = CASE(event.code == "7036" AND state LIKE "*stopped*", @timestamp, NULL),
       run_ts = CASE(event.code == "7036" AND state LIKE "*running*", @timestamp, NULL),
       problem_ts = CASE(problem IS NOT NULL, @timestamp, NULL),
       sig_age_days = TO_INTEGER(sig_age)
| STATS problems = VALUES(problem), first_problem = MIN(problem_ts), last_problem = MAX(problem_ts),
        last_stop = MAX(stop_ts), last_running = MAX(run_ts), max_sig_age = MAX(sig_age_days)
    BY host.name, component
| EVAL stayed_down = last_stop IS NOT NULL AND (last_running IS NULL OR last_running < last_stop)
                     AND DATE_DIFF("minute", last_stop, NOW()) >= 15,
       problem = CASE(stayed_down, "service stopped and not restarted", MV_FIRST(problems))
| WHERE first_problem IS NOT NULL OR stayed_down
| KEEP host.name, component, problem, problems, first_problem, last_problem, last_stop, last_running, max_sig_age
```

**How the parsing works.** The 1151 report is free text, so `GROK` takes the number after `Antivirus security intelligence age:`. The `< 10000` guard drops the `4294967295` value Defender writes for "never".

## Suppression
Suppress by `host.name`, `component`, `problem` for 24h. Alerts missing a key field are not suppressed. A broken host keeps logging the same failure until it's fixed. A different failure, or the other service, on the same host still alerts.

## Known false positives / exclusions
- **Stale signatures on laptops that were offline for a week.** The age drops on the first report after the laptop reconnects. If this is noisy, raise the threshold to 14 days rather than dropping the branch.
- **A host shut down straight after a service stop**, so no "running" event arrives. Check for a clean shutdown (System 1074 or 6006) before escalating.
- **Planned Defender removal** on machines being retired. Exclude by host name for the change window.

## Triage
- **Sense stopped or crashed** means the Defender for Endpoint EDR has gone dark. Treat it like CS05 or CP04 (Falcon not reporting) and check for tampering (W05, CP06) in the minutes before.
- **Engine crash or failed real-time protection on several hosts at once** is usually a bad platform update. Check the Defender release notes before treating it as an attack.
- **Stale signatures** are a coverage gap. Push an update (`Update-MpSignature`) and find out why the host isn't reaching the update source.

## Test
- On a lab host, `sc stop sense` (needs tamper protection off) and leave it stopped for 20 minutes.
- Block the Defender update URLs on a lab VM for 7 days, or check the existing health reports for an old host.
