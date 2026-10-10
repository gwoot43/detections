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
suppression:
  fields: [usr]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Changing an APM access policy, adding a local admin, or modifying an iRule on the VPN edge is a small set of actions by a small set of engineers. An unexpected one is either an attacker weakening the edge or an unmanaged change on a critical device.

## Prerequisite
The stock Elastic F5 BIG-IP integration (`f5_bigip`, data stream `logs-f5_bigip.log-*`) cannot feed this query as written:
- It has no audit data stream. It only parses F5 Telemetry Streaming JSON for LTM, AFM, APM, ASM, AVR, system and iHealth, plus ASM CEF. APM, for example, is parsed only from Telemetry Streaming JSON.
- Syslog lines are not parsed, whether they are TMOS/mcpd/tmsh audit lines or APM lines. They fail the JSON step, so the document gets `event.kind: pipeline_error` and the raw line is kept only in `event.original`. There is no `message` field and no user field.
- On APM events there is no username field, and the client IP and policy result are on separate records.

This rule needs a custom ingest pipeline (`logs-f5_bigip.log@custom`, which can parse `event.original`) or a custom syslog integration. That parser has to extract the audit message, the acting user, the client IP and the host. For APM lines it also has to extract the session ID, user, client IP and policy result. The index and field names in the query are the target names for that parser: `logs-f5.audit-*`, `message`, `f5.audit.user`/`user.name`, `source.ip` and `host.name`. If you use the `@custom` pipeline, the data stays in `logs-f5_bigip.log-*`, so change the `FROM` line to match.

## Query
```esql
FROM logs-f5.audit-* METADATA _id, _index, _version
| EVAL msg = TO_LOWER(TO_STRING(message)), usr = TO_LOWER(COALESCE(user.name, f5.audit.user))
| WHERE msg LIKE "*apm*policy*" OR msg LIKE "*access profile*" OR msg LIKE "*modify*auth*"
   OR msg LIKE "*create*user*" OR msg LIKE "*modify*user*" OR msg LIKE "*role*administrator*"
   OR msg LIKE "*irule*" OR msg LIKE "*sys*sshd*" OR msg LIKE "*modify*ltm*" OR msg LIKE "*tmsh*"
| WHERE NOT (usr IN ("svc-f5-backup", "svc-f5-monitoring"))
| KEEP @timestamp, host.name, usr, source.ip, message
```

## Suppression
Suppress by `usr` for 1h. Alerts missing a key field are not suppressed. An admin change session writes many audit lines.

## Known false positives / exclusions
- Backup and monitoring accounts, excluded above. Scheduled config sync between an HA pair.

## Triage
- Confirm against change control. An admin created or an access policy changed outside a window on the VPN edge is investigated as a potential compromise of the device.

## Test
Make a benign config change on a lab F5 and confirm the audit event ingests.
