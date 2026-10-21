---
id: C07
name: Azure VM run command, custom script extension or VMAccess password reset
category: cloud
status: todo
language: esql
index: logs-azure.activitylogs-*
mitre: [T1651, T1098, T1021.008]
data_source: Azure Activity log
suppression:
  fields: [actor, azure.resource.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Run Command and the Custom Script Extension execute as SYSTEM or root on the VM through the control plane. VMAccess resets the local admin password. Attackers with Contributor use these to bypass the OS entirely. Legitimate use is automation from known principals.

Extension writes are dominated by monitoring and security agents (Azure Monitor, Defender for Endpoint, dependency agents) that Azure Policy and Defender for Cloud deploy on their own. The rule keeps only the extension types that run a script or reset a credential.

## Query
```esql
FROM logs-azure.activitylogs-* METADATA _id, _index, _version
| EVAL op = TO_UPPER(azure.activitylogs.operation_name)
| WHERE op IN (
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION",
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMANDS/WRITE",
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE",
    "MICROSOFT.COMPUTE/VIRTUALMACHINESCALESETS/EXTENSIONS/WRITE",
    "MICROSOFT.HYBRIDCOMPUTE/MACHINES/EXTENSIONS/WRITE",
    "MICROSOFT.HYBRIDCOMPUTE/MACHINES/RUNCOMMANDS/WRITE"
  )
  AND event.outcome == "success"
// the extension type is in the resource ID (default name) or the request/response body (flattened properties)
| EVAL actor = COALESCE(azure.activitylogs.identity.claims_initiated_by_user.name, azure.activitylogs.identity.claims.appid),
       ext = TO_LOWER(CONCAT(COALESCE(azure.resource.id, ""), "|", COALESCE(TO_STRING(azure.activitylogs.properties), "")))
| WHERE op LIKE "*/RUNCOMMAND*"
    OR ext LIKE "*customscript*" OR ext LIKE "*vmaccess*" OR ext LIKE "*runcommand*"
// patching / automation service principals, by app ID
| WHERE COALESCE(azure.activitylogs.identity.claims.appid, "") NOT IN ("00000000-0000-0000-0000-000000000000")
| KEEP @timestamp, op, actor, azure.resource.name, azure.resource.group, azure.subscription_id, source.ip, _id, _version, _index
```

## Suppression
Suppress by `actor`, `azure.resource.name` for 1h. Alerts missing a key field are not suppressed. One run command or extension deploy writes several operations per VM. A different VM still alerts.

## Known false positives / exclusions
- Patch management or configuration tooling that pushes scripts through the Custom Script Extension or Run Command. Exclude its service principal by app ID in the inline list.
- Monitoring and security agent rollouts are already out: their extension types do not match.

## Triage
- Which VM, what script (the request body carries the command for Run Command), which identity.
- Pivot to CrowdStrike on that host for the resulting process tree (W-series rules).

## Test
Run `whoami` via Run Command on a test VM.
