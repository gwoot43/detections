---
id: IN04
name: eDiscovery or content search export, or search of another user's mailbox
category: insider
status: todo
severity: high
language: esql
index: logs-o365.audit-*
mitre: [T1114, T1213, T1530]
data_source: Microsoft 365 Unified Audit Log (eDiscovery / Purview)
suppression:
  fields: [usr]
  duration: 6h
  missing_fields: do_not_suppress
---
## Why this is high fidelity for insider risk
eDiscovery and content search let a privileged user search and export anyone's mailbox and SharePoint content across the tenant. An insider with compliance or admin rights can use it to read executives' mail or exfiltrate data wholesale. These actions are logged, and the population that should ever use them is tiny.

## Query
```esql
FROM logs-o365.audit-*
| WHERE event.dataset == "o365.audit"
  AND (o365.audit.Workload IN ("SecurityComplianceCenter", "Purview") OR event.action LIKE "Search*")
  AND event.action IN ("SearchCreated", "SearchStarted", "SearchExported", "SearchExportDownloaded",
                       "ViewedSearchExported", "SearchPreviewed", "ComplianceSearch", "NewComplianceSearch")
| EVAL usr = TO_LOWER(o365.audit.UserId)
| WHERE NOT (usr IN ("svc-ediscovery@yourdomain.com"))    // your sanctioned eDiscovery accounts
| KEEP @timestamp, usr, event.action, o365.audit.ObjectId, o365.audit.ClientIP
```
Keep this as a per-event alert, not a threshold: any export download outside the sanctioned accounts is worth review.

## Suppression
Suppress by `usr` for 6h. Alerts missing a key field are not suppressed. One search and export writes several events; a different user still alerts.

## Known false positives / exclusions
- The real eDiscovery and compliance team. Exclude their accounts inline. Everyone else using these features is the alert.

## Triage
- Confirm the user is authorised for eDiscovery. If not, this is a privileged insider reading or exporting others' data. Review the search scope and what was exported, and revoke the role.

## Test
Create and export a small content search in a lab tenant with a non-eDiscovery test account that has the role.
