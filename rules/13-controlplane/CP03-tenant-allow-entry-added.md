---
id: CP03
name: Tenant Allow/Block List allow entry added for a sender, domain, URL or file
category: controlplane
status: todo
severity: high
language: esql
index: logs-o365.audit-*
mitre: [T1562.001, T1556]
data_source: Microsoft 365 Unified Audit Log (Security and Compliance Center)
suppression:
  fields: [usr]
  duration: 6h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
An allow entry in the Tenant Allow/Block List tells Defender to stop filtering a sender, domain, URL or file hash. Attackers and tricked admins use it to whitelist their own phishing infrastructure so later mail sails through. Allow entries are rare and should be deliberate; a block entry is the normal, benign direction.

## Query
```esql
FROM logs-o365.audit-* METADATA _id, _index, _version
| WHERE event.dataset == "o365.audit"
  AND event.action IN ("New-TenantAllowBlockListItems", "Set-TenantAllowBlockListItems",
                       "New-TenantAllowBlockListSpoofItems")
| EVAL usr = TO_LOWER(o365.audit.UserId), params = TO_LOWER(TO_STRING(o365.audit.Parameters))
// keep allow entries; block entries are the benign direction
| WHERE params LIKE "*allow*" AND NOT (params LIKE "*block*true*")
| KEEP @timestamp, usr, event.action, params, o365.audit.ClientIP
```

## Suppression
Suppress by `usr` for 6h. Alerts missing a key field are not suppressed. One addition can write several lines; a different admin still alerts.

## Known false positives / exclusions
- Mail-ops legitimately allow-listing a mistaken block. Review each one; confirm the sender or domain is genuinely trusted and not attacker-controlled.

## Triage
- Read the allowed value. A newly registered domain, a lookalike sender or a URL on a hosting provider is attacker infrastructure. Remove the entry and hunt for mail from it (E01, E02).

## Test
Add and remove a benign allow entry in a lab tenant.
