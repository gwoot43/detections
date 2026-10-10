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
suppression:
  fields: [actor, azure.subscription_id]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
`beginGetAccess` on a managed disk or snapshot creates a SAS to download it, which is how attackers pull domain controller VHDs (ntds.dit) out of Azure. It is rare outside backup and migration tooling, so any principal doing it alerts. `listKeys` hands out full storage account access, but one engineer opening one account in the portal triggers it too. Harvesting looks different: one person reading or regenerating keys on three or more storage accounts in the same window.

## Query
Run hourly with a 1-hour lookback.
```esql
FROM logs-azure.activitylogs-*
| EVAL op = TO_UPPER(azure.activitylogs.operation_name)
| WHERE op IN (
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION",
    "MICROSOFT.STORAGE/STORAGEACCOUNTS/REGENERATEKEY/ACTION",
    "MICROSOFT.COMPUTE/DISKS/BEGINGETACCESS/ACTION",
    "MICROSOFT.COMPUTE/SNAPSHOTS/BEGINGETACCESS/ACTION"
  )
  AND event.outcome == "success"
| EVAL actor = COALESCE(azure.activitylogs.identity.claims_initiated_by_user.name, azure.activitylogs.identity.claims.appid),
       is_disk = CASE(op LIKE "*/BEGINGETACCESS/ACTION", 1, 0),
       is_human = CASE(azure.activitylogs.identity.claims_initiated_by_user.name LIKE "*@*", 1, 0)
// backup, migration and Terraform-state service principals, by app ID
| WHERE COALESCE(azure.activitylogs.identity.claims.appid, "") NOT IN ("00000000-0000-0000-0000-000000000000")
| STATS disk_exports = SUM(is_disk),
        key_accounts = COUNT_DISTINCT(CASE(is_disk == 0, azure.resource.name, NULL)),
        human = MAX(is_human),
        ops = VALUES(op), resources = VALUES(azure.resource.name), ips = VALUES(source.ip)
    BY actor, azure.subscription_id
| WHERE disk_exports > 0 OR (human == 1 AND key_accounts >= 3)
```
Snapshot creation and `allowBlobPublicAccess` changes were removed. Snapshots are written on schedule by backup tooling and are not an export, and public-access changes are a misconfiguration signal for a posture tool, not key or disk theft.

## Suppression
Suppress by `actor`, `azure.subscription_id` for 1h. Alerts missing a key field are not suppressed. Aggregating rule. Without suppression, overlapping lookbacks re-alert on the same activity.

## Known false positives / exclusions
- Backup, Azure Site Recovery or migration service principals that export disks. Exclude by app ID. Never exclude a human.
- An engineer working through several storage accounts in the portal during an incident or migration. Confirm against the change record.

## Triage
- Disk access on a domain controller or database VM is a critical incident. Revoke the SAS (`az disk revoke-access`) and check where the disk was downloaded from.
- For key harvesting, rotate the keys on every listed account and check the storage logs for data access with account keys afterwards.

## Test
Run `az storage account keys list` as your own user on three test accounts, or generate a SAS for a test disk.
