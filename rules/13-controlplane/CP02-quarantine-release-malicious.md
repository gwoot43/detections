---
id: CP02
name: Quarantine release of malicious mail, or release at volume
category: controlplane
status: todo
severity: high
language: esql
index: logs-o365.audit-*
mitre: [T1562, T1566]
data_source: Microsoft 365 Unified Audit Log (quarantine operations)
suppression:
  fields: [usr]
  duration: 6h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Releasing a message from quarantine puts it back in the user's inbox. Releasing one that Defender rated high-confidence phishing or malware, or releasing many messages at once, undoes the protection and is how a tricked admin or a malicious insider delivers a payload. Releases are infrequent and attributable.

## Query
```esql
FROM logs-o365.audit-* METADATA _id, _index, _version
| WHERE event.dataset == "o365.audit"
  AND event.action IN ("QuarantineRelease", "Release-QuarantineMessage", "QuarantineReleaseAll",
                       "QuarantineRequestRelease", "Preview-QuarantineMessage", "Export-QuarantineMessage")
| EVAL usr = TO_LOWER(o365.audit.UserId),
       detail = TO_LOWER(TO_STRING(COALESCE(o365.audit.Parameters, o365.audit.ExtendedProperties, ""))),
       malicious = detail LIKE "*malware*" OR detail LIKE "*highconfidencephish*" OR detail LIKE "*high confidence phish*" OR detail LIKE "*phish*"
| STATS releases = COUNT(*),
        malicious_releases = SUM(CASE(malicious, 1, 0)),
        recipients = COUNT_DISTINCT(o365.audit.ObjectId),
        actions = VALUES(event.action)
    BY usr, BUCKET(@timestamp, 1 hour)
| WHERE malicious_releases >= 1 OR releases >= 20
```
The quarantine verdict may sit in `Parameters` or `ExtendedProperties` depending on integration version; this checks both. If neither carries the verdict, alert on release volume alone and enrich at triage.

## Suppression
Suppress by `usr` for 6h. Alerts missing a key field are not suppressed. Aggregating rule. A release spree spans buckets; a different admin still alerts.

## Known false positives / exclusions
- The mail-operations team releasing confirmed false positives. Expected, but a release of a malware or high-confidence-phish verdict should still be reviewed each time; keep that branch.
- End-user self-release where your policy allows it. Scope to admin releases if self-release is common, or keep it and triage.

## Triage
- Pull the released message and its verdict. If it was malware or high-confidence phishing, purge it again from all recipients, check whether anyone interacted (E01, E04), and confirm the admin intended the release.

## Test
Release a benign quarantined test message in a lab tenant.
