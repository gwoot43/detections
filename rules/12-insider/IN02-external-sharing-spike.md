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
Sharing outside the tenant, or creating anonymous links, is how data leaves without a download on a managed device. A burst of distinct files shared to guests or personal email domains, or exposed through anonymous links, by one user is an exfiltration pattern. These operations are explicit audit events, so no Graph feed is needed.

## Query
Run hourly with a 1-hour lookback.
```esql
FROM logs-o365.audit-*
| WHERE event.provider IN ("SharePoint", "OneDrive")
  AND event.action IN ("AnonymousLinkCreated", "SharingInvitationCreated", "AddedToSecureLink", "SecureLinkCreated", "SharingSet")
| EVAL usr = TO_LOWER(o365.audit.UserId),
       target = TO_LOWER(COALESCE(o365.audit.TargetUserOrGroupName, "")),
       external = TO_LOWER(COALESCE(o365.audit.TargetUserOrGroupType, "")) == "guest"
                  OR target LIKE "*@gmail.com" OR target LIKE "*@outlook.com" OR target LIKE "*@hotmail.com"
                  OR target LIKE "*@proton*" OR target LIKE "*@yahoo.com" OR target LIKE "*@icloud.com",
       anon = event.action == "AnonymousLinkCreated"
| WHERE NOT usr IN ("app@sharepoint", "system account", "sharepoint\\system")
| STATS external_files = COUNT_DISTINCT(CASE(external, url.original, NULL)),
        anon_files = COUNT_DISTINCT(CASE(anon, url.original, NULL)),
        events = COUNT(*),
        targets = VALUES(CASE(external, target, NULL))
    BY usr, BUCKET(@timestamp, 1 hour)
| WHERE anon_files >= 5 OR external_files >= 10
```
Counts are distinct files (`url.original`, the integration's name for the file URL), because one share writes several events. `AnonymousLinkUsed` is left out (the actor is the anonymous visitor, not the sharer), and so is `CompanyLinkCreated` (an internal-only link).

## Suppression
Suppress by `usr` for 12h. Alerts missing a key field are not suppressed. Aggregating rule. Bulk sharing spans buckets; a different user still alerts.

## Known false positives / exclusions
- Teams and roles whose job is external collaboration (sales, legal, partnerships). Exclude those users inline, or raise their threshold, rather than turning the rule off.
- Sanctioned guest-sharing of specific sites. Exclude those `o365.audit.SiteUrl` values inline.

## Triage
- Sharing to a personal webmail address is the clearest signal; confirm the recipient and the content. Combine with IN01 for the same user.

## Test
Create a few anonymous links and share files to an external address as a test user.
