---
id: CS07
name: Scheduled tasks that matter — fleet rarity plus shape, not every registration
category: crowdstrike-fdr
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1053.005]
data_source: CrowdStrike FDR ScheduledTaskRegistered / ScheduledTaskModified events
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
Roughly every vendor on a Windows estate registers a task: Edge, Office, Defender, OneDrive, Adobe, the backup agent, the management agent. Alerting on registration is a change-log, and it will bury the one task that matters. The clean way is to stop treating "a task exists" as the signal and ask two questions instead:

**Is this task name rare?** A vendor task appears on the whole fleet. A task created by an attacker appears on one host, with a name that either invents something plausible or impersonates a system component (`SysMon`, `Microsoft\Windows\...` registered outside the system namespace).

**Does the action point anywhere a vendor would not put it?** User-writable directories, a script host with an encoded or URL argument, or a hidden task - vendors use `Program Files` and signed executables, and they do not hide their own tasks.

Either question alone has a benign twin: a bespoke admin script is rare and legitimate, and a vendor updater running `powershell.exe` from `ProgramData` is neither rare nor malicious. The pair is what makes this alertable.

```esql
FROM logs-yourorg-crowdstrike-data-default*
// One day, stated in the query. A vendor task rolls out over hours, not in one 15-minute bucket, so the
// rarity test needs a day to see the fleet. Run hourly with this lookback and aggregate repeats.
| WHERE @timestamp >= NOW() - 24 hours
  AND event.action IN ("scheduledtaskregistered", "scheduledtaskmodified")
  AND host.os.type == "windows"
| EVAL task = TO_LOWER(TO_STRING(COALESCE(data.TaskName, ""))),
       cmd = TO_LOWER(TO_STRING(COALESCE(data.TaskExecCommand, ""))),
       args = TO_LOWER(TO_STRING(COALESCE(data.TaskExecArguments, ""))),
       principal = TO_LOWER(TO_STRING(COALESCE(data.TaskPrincipalUser, ""))),
       payload = CONCAT(COALESCE(TO_STRING(data.TaskExecCommand), ""), " ", COALESCE(TO_STRING(data.TaskExecArguments), ""))
| EVAL payload = TO_LOWER(payload)
// Where a vendor would not put an action: user-writable directories.
| EVAL user_writable = payload LIKE """*\\appdata\\*""" OR payload LIKE """*\\temp\\*""" OR payload LIKE """*\\users\\public\\*"""
                       OR payload LIKE """*\\downloads\\*""" OR payload LIKE """*\\programdata\\*""",
// What a vendor would not do with it: encode it, fetch it, or hide the executing host.
       scripted = payload LIKE "*powershell*" OR payload LIKE "*pwsh*" OR payload LIKE "*wscript*"
                  OR payload LIKE "*cscript*" OR payload LIKE "*mshta*" OR payload LIKE "*rundll32*"
                  OR payload LIKE "*regsvr32*" OR payload LIKE "*certutil*" OR payload LIKE "*bitsadmin*"
                  OR payload LIKE "*curl*",
       encoded = payload LIKE "* -enc*" OR payload LIKE "*frombase64*" OR payload LIKE "* -e *",
// Impersonation: a monitoring- or Windows-sounding name that is not in the vendor's namespace.
       masquerade = (task LIKE "*sysmon*" OR task LIKE "*windows update*" OR task LIKE "*defender*"
                     OR task LIKE "*microsoft*" OR task LIKE "*onedrive*")
                    AND NOT task LIKE """\\microsoft\\windows\\*""",
// SYSTEM in a task created by a user is privilege escalation, not a vendor updater.
       system_principal = principal LIKE "*system*" OR principal LIKE "*s-1-5-18*"
| STATS registrations = COUNT(*),
        hosts = COUNT_DISTINCT(host.id, 10000),
        risky = COUNT(*) WHERE user_writable OR encoded OR masquerade,
        system_from_user = COUNT(*) WHERE system_principal AND (user_writable OR masquerade),
        payload_sample = MV_SLICE(VALUES(payload), 0, 4),
        names = MV_SLICE(VALUES(data.TaskName), 0, 3),
        principals = MV_SLICE(VALUES(data.TaskPrincipalUser), 0, 3),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY task
// Rare name AND a shape a vendor would not produce - or SYSTEM execution requested for a task that points at
// a user-writable path, which is the escalation case on its own. 2 hosts is a starting value: measure the
// estate's own task-name spread with the baseline below.
| WHERE (hosts <= 2 AND risky >= 1) OR system_from_user >= 1
| SORT registrations DESC
| LIMIT 100
```

Deploy hourly over the last 24 hours. Suppress by `task` for 24h; each run overlaps the last, so the repeats fold into the open alert.

## Why rarity is the right anchor
Count the row: `hosts <= 2` over a full day means no other machine in the estate registered a task with this name. That single condition removes the entire vendor population without a list - and lists of task names are the reason the old rule needed constant maintenance. The `risky` shape test then removes the remaining legitimate case, a bespoke script that an admin pinned to one server.

`masquerade` is deliberately narrow: it compares the name against the `\Microsoft\Windows\` namespace, because that is where the real system tasks live. A task called `SysMon` (the name in the October 2026 Cursor extension incident) registered in the root namespace is impersonation by construction, and it will never be `hosts > 2`.

## Reading the alert
- **`hosts`** is the whole story: `1` means nobody else has this task. Together with `risky` that is the alert.
- **`payload_sample`** shows the action. `powershell -enc`, `mshta http://`, or a `.cmd`/`.ps1` under `%APPDATA%` is execution; a signed vendor exe under `Program Files` is not, and it should not have reached here.
- **`principals`** is the privilege: `s-1-5-18` (SYSTEM) requested by a user context is escalation. `system_from_user` exists because that combination is worth alerting on even when the name is common.
- **`names`** shows the string actually registered, which is what you search the fleet for once confirmed.

## Nearest benign twins
- **A bespoke admin or monitoring script** an engineer pinned to one host. It is rare by definition, so `risky` has to hold it off: if it lives in `C:\ProgramData\Monitoring\` it will still fire - exclude that task name as an entity pair after the first alert.
- **Per-user installs** (browsers, chat clients installed without admin) that register tasks under `%LOCALAPPDATA%`. Multiple hosts, but not necessarily the whole fleet - the reason `hosts <= 2` is a starting value and the baseline matters.
- **A vendor rolling out in stages**, where the first host shows `hosts = 1` for a few hours. Its action points into `Program Files`, so `risky` is 0 and it does not alert.
- **Backup agents creating per-host tasks** with host-specific names. Rare per name, legitimate per vendor - `risky` again, and an entity pair if the action path looks odd.

## What it misses
- **A task that already exists being re-pointed** without a modification event, or one created by a mechanism that does not emit `scheduledtaskmodified`.
- **Tasks in the `\Microsoft\Windows\` namespace** used for real: the masquerade test gives that namespace a pass, which is where a patient attacker would put it. The `system_from_user` branch is the only cover there.
- **Linux.** `cron`, `@reboot` and systemd timers are not in this feed; the Cursor loader's Linux persistence (`@reboot` crontab entry) needs file or audit telemetry.
- **Registry-based persistence** - that is `registry-writes-that-matter.md`.
- **Task deletion and disable** used as defence evasion; deletions are a different event.

## Baseline
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 7 days
  AND event.action IN ("scheduledtaskregistered", "scheduledtaskmodified")
  AND host.os.type == "windows"
| EVAL task = TO_LOWER(TO_STRING(COALESCE(data.TaskName, "")))
| STATS registrations = COUNT(*), hosts = COUNT_DISTINCT(host.id, 10000) BY task
| SORT hosts ASC, registrations DESC
| LIMIT 60
```
Read the top of this list before tuning: it is every task name in the estate with how many hosts registered it. Anything at `hosts` 1-2 that is not in `Program Files` is the population this rule alerts on, and the ones that look legitimate are your entity pairs.

## Probe before enabling
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 24 hours
  AND event.action IN ("scheduledtaskregistered", "scheduledtaskmodified")
| STATS events = COUNT(*), with_action = COUNT(*) WHERE data.TaskExecCommand IS NOT NULL,
        with_name = COUNT(*) WHERE data.TaskName IS NOT NULL,
        with_principal = COUNT(*) WHERE data.TaskPrincipalUser IS NOT NULL
    BY host.os.type
```
If `with_action` is zero, the task action is not parsed on this pipeline and the shape test cannot work - the fallback is `data.TaskXml` (the raw definition), which carries the action, the principal and the `Hidden` flag in one string, at the cost of regex work in `EVAL`.
<br>

## References
- `rules/07-crowdstrike-fdr/CS07` - the earlier payload-filtered task rule; this one adds the fleet-rarity anchor and impersonation
- MITRE T1053.005 (scheduled task), T1036 (masquerading), T1055-adjacent privilege context via `s4u`/SYSTEM principal
- Microsoft Threat Intelligence, October 2026 Cursor extension incident - a task named `SysMon` requesting SYSTEM execution, which is the masquerade case above
- `registry-writes-that-matter.md` - the same "rare writer, shaped target" design applied to the registry
