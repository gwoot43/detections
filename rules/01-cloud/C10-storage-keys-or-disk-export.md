---
id: C10
name: Storage account keys listed, disk SAS generated or snapshot exported by unusual principal
category: cloud
status: todo
severity: high
language: esql
index: logs-azure.activitylogs-*
mitre: [T1530, T1552, T1005]
data_source: Azure Activity log
---
## Why this is high fidelity
`listKeys` hands out full storage account access. `beginGetAccess` on a managed disk creates a SAS to download the VM's disk, which is how attackers pull domain controller VHDs (ntds.dit) out of Azure. Both are rare outside automation.

## Query
```esql
FROM logs-azure.activitylogs-* METADATA _id, _index, _version
| EVAL op = TO_UPPER(azure.activitylogs.operation_name)
| WHERE op IN (
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION",
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION",
    "MICROSOFT.COMPUTE/DISKS/BEGINGETACCESS/ACTION",
    "MICROSOFT.COMPUTE/SNAPSHOTS/BEGINGETACCESS/ACTION",
    "MICROSOFT.COMPUTE/SNAPSHOTS/WRITE",
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE"      // check body for allowBlobPublicAccess:true
  )
  AND event.outcome IN ("success", "Success")
| EVAL actor = COALESCE(azure.activitylogs.identity.claims_initiated_by_user.name, azure.activitylogs.identity.claims.appid),
       body  = TO_LOWER(TO_STRING(azure.activitylogs.properties.requestbody))
| WHERE NOT (op == "MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE") OR body LIKE "*\"allowblobpublicaccess\":true*"
// baseline: count per actor over the rule window, alert on humans and on any principal doing disk access
| STATS n = COUNT(*), ops = VALUES(op), resources = VALUES(azure.resource.name), ips = VALUES(source.ip)
    BY actor, azure.subscription_id
| WHERE (actor LIKE "*@*") OR (MV_CONCAT(ops, ",") LIKE "*BEGINGETACCESS*") OR (MV_CONCAT(ops, ",") LIKE "*SNAPSHOTS/WRITE*")
```

## Known false positives / exclusions
- Backup vault and Terraform state service principals for `listKeys`. Exclude by appid. Never exclude a human.
- Azure Backup creates snapshots on schedule under its own principal.

## Triage
- Disk access on a domain controller or database VM is a critical incident. Rotate keys for `listKeys` on sensitive accounts and revoke the SAS.

## Test
Run `az storage account keys list` as your own user on a test account.
