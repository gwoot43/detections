---
id: D03
name: Decoy SharePoint/OneDrive file or Confluence page opened, previewed, downloaded or copied
category: deception
status: todo
rank: 2
language: esql
index: logs-o365.audit-*
mitre: [T1213.002, T1552.001, T1083]
data_source: Microsoft 365 unified audit log (SharePoint and OneDrive file events). Confluence Data Center access log (option B).
suppression:
  fields: [usr, file.name]
  duration: 4h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A decoy file such as "IT Ops - break glass accounts.xlsx" or "VPN service creds.docx", on a broadly readable site, has no business purpose. Nobody is told it exists, it isn't linked anywhere, and it only turns up for someone searching for credentials. Opening it is a strong signal on its own. Using the honey credentials inside it then fires D01 or D02 as well, which confirms the alert.

This is the precise version of IN09, which looks for sensitive-keyword searches followed by access. This rule only needs one open of one file.

## Prerequisite
- The unified audit log must be on and ingested (it already is for the IN rules). `FileAccessed` and `FilePreviewed` are included in Audit Standard.
- Give each decoy file a name nothing else in the tenant shares, and replace the placeholders in the deployed rule only.
- **Test the noise before go-live.** SharePoint's own search crawler, thumbnail generation, DLP scanning and backup products touch new files under service identities. The `usr` exclusions below cover the common ones. Run the rule in preview for a week after placing the file, and add any service identity you see.

## Query
**Option A: SharePoint and OneDrive**
```esql
FROM logs-o365.audit-* METADATA _id, _index, _version
| WHERE event.provider IN ("SharePoint", "OneDrive")
  AND event.action IN ("FileAccessed", "FileAccessedExtended", "FilePreviewed", "FileDownloaded",
                       "FileSyncDownloadedFull", "FileSyncDownloadedPartial", "FileCopied", "FileMoved")
| WHERE file.name IN ("<decoy_file_1.xlsx>", "<decoy_file_2.docx>")
| EVAL usr = TO_LOWER(COALESCE(o365.audit.UserId, user.email, user.name, "")),
       ua = TO_LOWER(COALESCE(user_agent.original, ""))
| WHERE NOT (usr IN ("app@sharepoint", "system account", "sharepoint\\system") OR usr LIKE "*@sharepoint")
  AND NOT ua LIKE "*ms-search*" AND NOT ua LIKE "*backup*"
| KEEP @timestamp, usr, event.action, file.name, url.original, o365.audit.SiteUrl, source.ip, user_agent.original, _id, _version, _index
```

Field notes: the O365 integration moves `Workload` to `event.provider`, the file's full URL (`ObjectId`) to `url.original`, and `ClientIP` to `source.ip`. The `o365.audit.*` copies of those three are empty, so a filter on `o365.audit.Workload` never matches. `file.name` is compared exactly, including case.

**Option B: Confluence Data Center**

Confluence **Cloud** audit logs don't record page views, so on Cloud rely on the credentials inside the page firing D01 or D02. On **Data Center**, the Tomcat access log (`<confluence-home>/logs/atlassian-confluence-access.log`) records each request URL. Ship it with an Elastic Agent custom log input that parses the access log into `url.*`, `user.name` and `source.ip`, then:
```esql
FROM logs-confluence.access-*
| EVAL u = TO_LOWER(COALESCE(url.original, url.path, ""))
| WHERE u LIKE "*pageid=<decoy_page_id>*" OR u LIKE "*/<decoy_space_key>/<decoy_page_title_slug>*"
| STATS views = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), urls = VALUES(u)
    BY user.name, source.ip
```
Use the page ID: it doesn't change when the page is renamed. Exclude the Confluence search indexer and any backup service account by `user.name`.

## Suppression
Suppress by `usr`, `file.name` for 4h. Alerts missing a key field are not suppressed. Opening a workbook writes several events (accessed, previewed, then downloaded). A different user or a different decoy still alerts.

## Known false positives / exclusions
- **Microsoft 365 Copilot** retrieves files on behalf of the user who asked. A user who asked Copilot about "break glass accounts" is an interesting case too. Review it rather than excluding it.
- **eDiscovery or content searches** by the compliance team show up as the reviewer opening the file. IN04 records the search itself.
- **Site owners** may stumble on the file while tidying. Pick a site where the owners are briefed, or are part of the white cell.

## Triage
- Who opened it (`usr`), from where (`source.ip`, user agent), and what else did they search for and open in the hour before (IN07, IN09)? A red team operator or attacker typically searches "password", "creds", "vpn" or "break glass" first.
- Check whether the honey credentials in the file were then tried (D01, D02). Opened and tried confirms intent. Opened and not tried may still be curiosity.

## Test
Open the decoy file in the browser from a lab user and confirm one `FileAccessed` (or `FilePreviewed`) arrives under that user within the audit log's usual 30-60 minute delay.
