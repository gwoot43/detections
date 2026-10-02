---
id: IN09
name: SharePoint search for secrets followed by sensitive file access or bulk download
category: insider
status: todo
severity: high
language: esql
index: logs-o365.audit-*
mitre: [T1213.002, T1552.001, T1083]
data_source: Microsoft 365 Unified Audit Log (SharePoint search and file operations)
suppression:
  fields: [usr]
  duration: 12h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Someone hunting for credentials searches SharePoint for terms like "password", "api key" or ".env", then opens or downloads what the search turned up. A search alone is often innocent, and so is opening a few files. This rule requires both, in order: a search for secrets, then shortly afterwards either a file whose name looks like a secret, or a bulk download. Help-desk searches such as "password reset" are excluded.

## Prerequisite
`SearchQueryInitiatedSharePoint` is an Audit (Premium) event and is not recorded for every user. Confirm it exists before enabling: count `event.action == "SearchQueryInitiatedSharePoint"` over a week. If it is absent the rule never fires.

## Query
Run hourly with a 2-hour lookback. File activity must come within 30 minutes after the user's first secret search. `INLINE STATS` needs a recent Elastic release; use the fallback below if yours lacks it.
```esql
FROM logs-o365.audit-*
| EVAL act = TO_LOWER(event.action),
       usr = TO_LOWER(COALESCE(user.email, user.name)),
       q = TO_LOWER(COALESCE(QueryText, "")),
       fname = TO_LOWER(COALESCE(file.name, ""))
| WHERE act IN ("searchqueryinitiatedsharepoint", "filedownloaded", "filesyncdownloadedfull", "fileaccessed")
  AND NOT (usr LIKE "app@sharepoint*" OR usr == "system account")
| EVAL secret_term = q LIKE "*password*" OR q LIKE "*passwd*" OR q LIKE "*credential*" OR q LIKE "*secret*"
                     OR q LIKE "*api key*" OR q LIKE "*apikey*" OR q LIKE "*token*" OR q LIKE "*id_rsa*"
                     OR q LIKE "*.env*" OR q LIKE "*private key*" OR q LIKE "*connection string*"
                     OR q LIKE "*.pem*" OR q LIKE "*.kdbx*" OR q LIKE "*keepass*",
       helpdesk = q LIKE "*reset*" OR q LIKE "*how to*" OR q LIKE "*wifi*" OR q LIKE "*byod*" OR q LIKE "*policy*",
       sensitive_search = act == "searchqueryinitiatedsharepoint" AND secret_term AND NOT helpdesk,
       sensitive_file = act != "searchqueryinitiatedsharepoint"
                        AND (fname LIKE "*password*" OR fname LIKE "*credential*" OR fname LIKE "*secret*"
                             OR fname LIKE "*.env" OR fname LIKE "*.pem" OR fname LIKE "*.key" OR fname LIKE "*.pfx"
                             OR fname LIKE "*.kdbx" OR fname LIKE "*id_rsa*"),
       download = act IN ("filedownloaded", "filesyncdownloadedfull")
| INLINE STATS first_search = MIN(CASE(sensitive_search, @timestamp, NULL)) BY usr
| WHERE first_search IS NOT NULL
| EVAL mins_after = DATE_DIFF("minute", first_search, @timestamp),
       in_window = (sensitive_file OR download) AND mins_after >= 0 AND mins_after <= 30
| WHERE sensitive_search OR in_window
| STATS sensitive_searches = SUM(CASE(sensitive_search, 1, 0)),
        search_terms = VALUES(CASE(sensitive_search, q, NULL)),
        first_search = MIN(first_search),
        sensitive_files = COUNT_DISTINCT(CASE(in_window AND sensitive_file, fname, NULL)),
        downloads = COUNT_DISTINCT(CASE(in_window AND download, fname, NULL)),
        file_names = VALUES(CASE(in_window, fname, NULL)),
        ips = VALUES(source.ip)
    BY usr
| WHERE sensitive_searches >= 1 AND (sensitive_files >= 1 OR downloads >= 25)
```

### Fallback without INLINE STATS
Any file activity after the search within the lookback counts. Shorten the lookback (for example every 15 minutes over 45 minutes) to tighten the link.
```esql
FROM logs-o365.audit-*
| EVAL act = TO_LOWER(event.action),
       usr = TO_LOWER(COALESCE(user.email, user.name)),
       q = TO_LOWER(COALESCE(QueryText, "")),
       fname = TO_LOWER(COALESCE(file.name, ""))
| WHERE act IN ("searchqueryinitiatedsharepoint", "filedownloaded", "filesyncdownloadedfull", "fileaccessed")
  AND NOT (usr LIKE "app@sharepoint*" OR usr == "system account")
| EVAL secret_term = q LIKE "*password*" OR q LIKE "*passwd*" OR q LIKE "*credential*" OR q LIKE "*secret*"
                     OR q LIKE "*api key*" OR q LIKE "*apikey*" OR q LIKE "*token*" OR q LIKE "*id_rsa*"
                     OR q LIKE "*.env*" OR q LIKE "*private key*" OR q LIKE "*connection string*"
                     OR q LIKE "*.pem*" OR q LIKE "*.kdbx*" OR q LIKE "*keepass*",
       helpdesk = q LIKE "*reset*" OR q LIKE "*how to*" OR q LIKE "*wifi*" OR q LIKE "*byod*" OR q LIKE "*policy*",
       sensitive_search = act == "searchqueryinitiatedsharepoint" AND secret_term AND NOT helpdesk,
       sensitive_file = act != "searchqueryinitiatedsharepoint"
                        AND (fname LIKE "*password*" OR fname LIKE "*credential*" OR fname LIKE "*secret*"
                             OR fname LIKE "*.env" OR fname LIKE "*.pem" OR fname LIKE "*.key" OR fname LIKE "*.pfx"
                             OR fname LIKE "*.kdbx" OR fname LIKE "*id_rsa*"),
       download = act IN ("filedownloaded", "filesyncdownloadedfull")
| STATS sensitive_searches = SUM(CASE(sensitive_search, 1, 0)),
        search_terms = VALUES(CASE(sensitive_search, q, NULL)),
        first_search = MIN(CASE(sensitive_search, @timestamp, NULL)),
        sensitive_files = COUNT_DISTINCT(CASE(sensitive_file, fname, NULL)),
        downloads = COUNT_DISTINCT(CASE(download, fname, NULL)),
        last_file = MAX(CASE(sensitive_file OR download, @timestamp, NULL)),
        ips = VALUES(source.ip)
    BY usr
| WHERE sensitive_searches >= 1 AND last_file >= first_search
  AND (sensitive_files >= 1 OR downloads >= 25)
```
In this version the file counts include activity from before the search; only the ordering check uses the latest file event.

## Suppression
Suppress by `usr` for 12h. Alerts missing a key field are not suppressed. Aggregating rule; overlapping runs would otherwise re-alert on the same activity.

## Known false positives / exclusions
- IT, security and DevOps staff who legitimately search for credential documentation. Exclude them inline by user, or route them to a lower-priority queue.
- Files are counted by name, so same-named files on different sites count once. If you have a full URL or path field, count that instead.
- Tune the keyword and help-desk lists on two weeks of real searches before enabling.

## Triage
- Read `search_terms` and `file_names` together. A search for "aws secret" followed by opening `prod.env` is credential hunting. Rotate any secrets in the opened files, then check whether the user downloaded more (IN01) or shared externally (IN02).

## Test
As a test user, search SharePoint for "service account password", then open a file named `credentials.txt` within 30 minutes.
