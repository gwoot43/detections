---
id: CP03
name: Tenant Allow/Block List allow entry added for a sender, domain, URL, file or spoofed sender
category: controlplane
status: todo
language: esql
index: logs-o365.audit-*
mitre: [T1685, T1556]
data_source: Microsoft 365 Unified Audit Log (Exchange admin)
suppression:
  fields: [usr]
  duration: 6h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
An allow entry in the Tenant Allow/Block List tells Defender to stop filtering a sender, domain, URL or file hash. Attackers and tricked admins use it to whitelist their own phishing infrastructure so later mail sails through. Allow entries are rare and should be deliberate; a block entry is the normal, benign direction and is excluded.

## Prerequisite
`o365.audit.Parameters.Allow` (the `-Allow` switch), `Action` (spoofed-sender entries) and `Entries` are mapped only after the first event that uses them. If one is missing, the query fails with "Unknown column". Map them as `keyword` in the `logs-o365.audit@custom` component template; `Allow` in particular may never have been used on your tenant.

## Query
```esql
FROM logs-o365.audit-* METADATA _id, _index, _version
| WHERE event.outcome == "success"
  AND event.action IN ("New-TenantAllowBlockListItems", "Set-TenantAllowBlockListItems", "New-TenantAllowBlockListSpoofItems")
| EVAL usr = TO_LOWER(o365.audit.UserId),
       allow = TO_LOWER(COALESCE(o365.audit.Parameters.Allow, "")) == "true"
               OR TO_LOWER(COALESCE(o365.audit.Parameters.Action, "")) == "allow"
| WHERE allow
| KEEP @timestamp, usr, event.action, o365.audit.Parameters.Entries, o365.audit.ObjectId, source.ip, _id, _version, _index
```
`New-TenantAllowBlockListItems` takes `-Allow` or `-Block`; spoof entries take `-Action Allow` or `-Action Block`. Only the allow direction is kept.

## Suppression
Suppress by `usr` for 6h. Alerts missing a key field are not suppressed. One addition can write several lines; a different admin still alerts.

## Known false positives / exclusions
- Mail-ops allow-listing a sender after a confirmed false-positive block. Review each one; confirm the sender or domain is genuinely trusted and not attacker-controlled.

## Triage
- Read the allowed value (`Entries`, or the spoofed sender in `ObjectId`). A newly registered domain, a lookalike sender or a URL on a hosting provider is attacker infrastructure. Remove the entry and hunt for mail from it (E01, E02).

## Test
Add and remove a benign allow entry in a lab tenant.
