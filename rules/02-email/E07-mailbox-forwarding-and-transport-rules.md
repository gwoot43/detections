---
id: E07
name: Mailbox forwarding to an external address, or transport rule that redirects or BCCs mail out
category: email
status: todo
severity: high
language: esql
index: logs-o365.audit-*
mitre: [T1114.003]
data_source: Microsoft 365 Unified Audit Log (Exchange admin audit)
suppression:
  fields: [o365.audit.UserId, o365.audit.ObjectId]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
`Set-Mailbox -ForwardingSmtpAddress` and transport rules with `RedirectMessageTo` or `BlindCopyTo` are organisation-level exfiltration channels that survive the user's password reset. The rule keeps only targets outside your domain, plus new journal rules and remote domains opened to auto-forwarding. These are admin actions with a very small legitimate population.

## Prerequisite
The parameters below are mapped only after the first event that uses them is ingested: `ForwardingSmtpAddress`, `RedirectMessageTo`, `BlindCopyTo`, `AutoForwardEnabled` (all under `o365.audit.Parameters.`). If one is missing, the query fails with "Unknown column". Map them as `keyword` in the `logs-o365.audit@custom` component template.

## Query
```esql
FROM logs-o365.audit-* METADATA _id, _index, _version
| WHERE event.provider == "Exchange" AND event.outcome == "success"
  AND event.action IN ("Set-Mailbox", "New-TransportRule", "Set-TransportRule", "New-JournalRule", "Set-RemoteDomain")
| EVAL target = TO_LOWER(CASE(
         event.action == "Set-Mailbox", COALESCE(o365.audit.Parameters.ForwardingSmtpAddress, ""),
         event.action LIKE "*TransportRule", CONCAT(COALESCE(o365.audit.Parameters.RedirectMessageTo, ""), ";",
                                                    COALESCE(o365.audit.Parameters.BlindCopyTo, "")),
         "")),
       auto_forward = TO_LOWER(COALESCE(o365.audit.Parameters.AutoForwardEnabled, ""))
// drop internal addresses; any address left is external
| EVAL external = REPLACE(target, "[a-z0-9._%+'-]+@yourdomain\\.com", "") LIKE "*@*"
| WHERE (event.action IN ("Set-Mailbox", "New-TransportRule", "Set-TransportRule") AND external)
     OR event.action == "New-JournalRule"
     OR (event.action == "Set-RemoteDomain" AND auto_forward == "true")
| KEEP @timestamp, o365.audit.UserId, source.ip, event.action, o365.audit.ObjectId, target, auto_forward, _id, _version, _index
```
Clearing forwarding sends an empty value, which the integration drops, so removals never match.

## Suppression
Suppress by `o365.audit.UserId`, `o365.audit.ObjectId` for 1h. Alerts missing a key field are not suppressed. Admin scripts re-apply the same setting.

## Known false positives / exclusions
- Leaver forwarding to a manager is internal and excluded. Add your other accepted domains to the `REPLACE` pattern.
- Compliance journaling to an external archive. Ticket-gated, not excluded.

## Triage
- Remove the forwarding, identify the admin session (`source.ip`), and look for a matching privileged role assignment (C03) or credential add (C04).

## Test
Set and clear `ForwardingSmtpAddress` to an external test address on a lab mailbox.
