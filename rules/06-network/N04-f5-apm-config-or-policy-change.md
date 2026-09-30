---
id: N04
name: F5 APM/TMOS administrative change or access policy modification
category: network
status: todo
severity: high
language: esql
index: logs-f5.audit-*
mitre: [T1556, T1562.001, T1078]
data_source: F5 TMOS/APM audit (MCP audit) logs
---
## Why this is high fidelity
Changing an APM access policy, adding a local admin, or modifying an iRule on the VPN edge is a small set of actions by a small set of engineers. An unexpected one is either an attacker weakening the edge or an unmanaged change on a critical device.

## Query
```esql
FROM logs-f5.audit-*
| EVAL msg = TO_LOWER(TO_STRING(message)), usr = TO_LOWER(COALESCE(user.name, f5.audit.user))
| WHERE msg LIKE "*apm*policy*" OR msg LIKE "*access profile*" OR msg LIKE "*modify*auth*"
   OR msg LIKE "*create*user*" OR msg LIKE "*modify*user*" OR msg LIKE "*role*administrator*"
   OR msg LIKE "*irule*" OR msg LIKE "*sys*sshd*" OR msg LIKE "*modify*ltm*" OR msg LIKE "*tmsh*"
| WHERE NOT (usr IN ("svc-f5-backup", "svc-f5-monitoring"))
| KEEP @timestamp, host.name, usr, source.ip, message
```

## Known false positives / exclusions
- Backup and monitoring accounts, excluded above. Scheduled config sync between an HA pair.

## Triage
- Confirm against change control. An admin created or an access policy changed outside a window on the VPN edge is investigated as a potential compromise of the device.

## Test
Make a benign config change on a lab F5 and confirm the audit event ingests.
