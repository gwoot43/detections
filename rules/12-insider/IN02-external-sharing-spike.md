---
id: IN02
name: External or anonymous sharing of SharePoint/OneDrive content at volume
category: insider
status: todo
severity: high
language: esql
index: logs-o365.audit-*
mitre: [T1213.002, T1537, T1567]
data_source: Microsoft 365 Unified Audit Log (SharePoint sharing operations)
suppression:
  fields: [usr]
  duration: 12h
  missing_fields: do_not_suppress
---
## Why this is high fidelity for insider risk
Sharing to outside the tenant, or creating anonymous links, is how data leaves without a download on a managed device. A burst of external or anonymous sharing by one user, or sharing to a personal email domain, is an exfiltration pattern. These operations are explicit audit events, so no Graph feed is needed.

## Query
Run hourly with a 1-hour lookback.
```esql
FROM logs-o365.audit-*
| WHERE event.dataset == "o365.audit" AND o365.audit.Workload IN ("SharePoint", "OneDrive")
  AND event.action IN ("AnonymousLinkCreated", "AnonymousLinkUsed", "SharingInvitationCreated",
                       "AddedToSecureLink", "SecureLinkCreated", "CompanyLinkCreated", "SharingSet")
| EVAL usr = TO_LOWER(o365.audit.UserId),
       target = TO_LOWER(TO_STRING(o365.audit.TargetUserOrGroupName)),
       external = CASE(TO_STRING(o365.audit.TargetUserOrGroupType) == "Guest"
                       OR target LIKE "*gmail.com" OR target LIKE "*outlook.com" OR target LIKE "*hotmail.com"
                       OR target LIKE "*proton*" OR target LIKE "*yahoo.com" OR target LIKE "*icloud.com", 1, 0),
       anon = CASE(event.action LIKE "Anonymous*", 1, 0)
| WHERE NOT (usr LIKE "app@sharepoint" OR usr == "system account")
| STATS external_shares = SUM(external), anon_links = SUM(anon), total = COUNT(*),
        files = COUNT_DISTINCT(o365.audit.ObjectId),
        targets = VALUES(target)
    BY usr, BUCKET(@timestamp, 1 hour)
| WHERE anon_links >= 5 OR external_shares >= 10
```

## Suppression
Suppress by `usr` for 12h. Alerts missing a key field are not suppressed. Aggregating rule. Bulk sharing spans buckets; a different user still alerts.

## Known false positives / exclusions
- Teams and roles whose job is external collaboration (sales, legal, partnerships). Exclude those users inline, or raise their threshold, rather than turning the rule off.
- Sanctioned guest-sharing of specific sites. Exclude those site URLs inline.

## Triage
- Sharing to a personal webmail address is the clearest signal; confirm the recipient and the content. Combine with IN01 for the same user.

## Test
Create a few anonymous links and share files to an external address as a test user.
