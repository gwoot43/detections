---
id: CS07
name: Scheduled task created or modified pointing at a suspicious payload
category: crowdstrike-fdr
status: todo
severity: high
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1053.005]
data_source: CrowdStrike FDR ScheduledTaskRegistered / ScheduledTaskModified events
suppression:
  fields: [host.id, payload]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Falcon has dedicated events for task registration and modification, which is cleaner than parsing `schtasks.exe` command lines. The payload decides fidelity: a task running from a user-writable path, an HTML application, an encoded or Base64 command, or a script host fetching a URL is persistence.

Services are not covered here. WE08 owns service installs: it reads 7045/4697 on every host, alerts fleet-wide on services from user-writable paths or running a shell, and on any new service on a domain controller.

Task events carry the action in `data.TaskExecCommand` and `data.TaskExecArguments`, not in `process.command_line`. Plain `powershell` or `cmd /c` in a task is not enough on its own; vendor and admin tasks use both every day. Defender's platform folder and OneDrive's per-user updater are excluded because they re-register their tasks on every update.

## Query
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action IN ("scheduledtaskregistered", "scheduledtaskmodified") AND host.os.type == "windows"
| EVAL payload = TO_LOWER(CONCAT(COALESCE(data.TaskExecCommand, ""), " ", COALESCE(data.TaskExecArguments, "")))
| EVAL script_host = payload LIKE "*powershell*" OR payload LIKE "*pwsh*" OR payload LIKE "*wscript*" OR payload LIKE "*cscript*"
                     OR payload LIKE "*rundll32*" OR payload LIKE "*regsvr32*" OR payload LIKE "*certutil*" OR payload LIKE "*bitsadmin*" OR payload LIKE "*curl*"
| WHERE (payload LIKE """*\\temp\\*""" OR payload LIKE """*\\appdata\\*""" OR payload LIKE """*\\programdata\\*""" OR payload LIKE """*\\users\\public\\*""" OR payload LIKE """*\\downloads\\*""")
     OR payload LIKE "*mshta*" OR payload LIKE "*.hta*" OR payload LIKE "*frombase64*"
     OR (script_host AND (payload LIKE "*http*" OR payload LIKE "* -enc*" OR payload LIKE "* -e *" OR payload LIKE "*hidden*"))
| WHERE NOT (payload LIKE """*\\programdata\\microsoft\\windows defender\\platform\\*""" OR payload LIKE """*\\appdata\\local\\microsoft\\onedrive\\*""")
| KEEP @timestamp, host.id, host.name, user.name, event.action, data.TaskName, payload, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ScheduledTaskRegistered|ScheduledTaskModified)$/ event_platform=Win
| default(field=TaskExecCommand, value="")
| default(field=TaskExecArguments, value="")
| payload := format("%s %s", field=[TaskExecCommand, TaskExecArguments])
| payload := lower(payload)
| payload=/\\temp\\|\\appdata\\|\\programdata\\|\\users\\public\\|\\downloads\\|mshta|\.hta|frombase64/
    OR (payload=/powershell|pwsh|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|curl/ AND payload=/http| -enc| -e |hidden/)
| payload!=/\\programdata\\microsoft\\windows defender\\platform\\|\\appdata\\local\\microsoft\\onedrive\\/
| table([@timestamp, aid, ComputerName, UserName, #event_simpleName, TaskName, payload])
```

## Suppression
Suppress by `host.id`, `payload` for 24h. Alerts missing a key field are not suppressed. Tasks re-register on update. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- Software updaters that register tasks in `Program Files`. The payload filter targets user-writable and script paths, excluding most. Per-user updaters that run from `%LOCALAPPDATA%` (browsers installed per user, Zoom, Slack) are the main remaining noise; exclude their exact path or `data.TaskName`.

## Triage
- Read the task action (`payload`, and the full `data.TaskXml` in Discover), find the payload, remove it, and check for the same payload on other hosts (fleet sweep).

## Test
Register a scheduled task on a lab host whose action runs a script from `%TEMP%`, confirm the alert, then delete the task.
