---
id: C07
name: Azure VM run command, custom script extension or VMAccess password reset
category: cloud
status: todo
severity: high
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
  AND event.outcome IN ("success", "Success")
| EVAL actor = COALESCE(azure.activitylogs.identity.claims_initiated_by_user.name, azure.activitylogs.identity.claims.appid)
| WHERE NOT (actor IN ("sp-vm-patching@yourtenant.onmicrosoft.com"))
| KEEP @timestamp, op, actor, azure.resource.name, azure.resource.group, azure.subscription_id, source.ip
```

## Suppression
Suppress by `actor`, `azure.resource.name` for 1h. Alerts missing a key field are not suppressed. One run command or extension deploy writes several operations per VM. A different VM still alerts.

## Known false positives / exclusions
- Patch management, monitoring agent rollout, Defender for Cloud auto-provisioning. Exclude by service principal and by extension publisher (`Microsoft.Azure.Monitor`, `Microsoft.Azure.Security`) once you can see the extension name in `properties.requestbody`.

## Triage
- Which VM, what script (requestbody carries the command for runCommand), which identity.
- Pivot to CrowdStrike on that host for the resulting process tree (W-series rules).

## Test
Run `whoami` via Run Command on a test VM.
