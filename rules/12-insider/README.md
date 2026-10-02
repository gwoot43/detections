# Insider-risk detections

Detections for data theft, snooping and sabotage by people who already have access. Sources are the Microsoft 365 Unified Audit Log (SharePoint, OneDrive, Exchange, Purview), Confluence audit logs, and the outbound mail gateway. They do not depend on any Microsoft Graph API feed.

Notes for this folder:
- **No lookups or custom indexes.** Exclusions and domains are written inline. Where a per-user baseline would help (snooping breadth, download volume), a fixed threshold is used instead and should be tuned on two weeks of data.
- **Context is the deciding factor.** Insider alerts are strongest when joined to HR context (notice period, role, team). That join is a process step for the analyst, not something these log-only rules can do alone.
- **Azure insider data access** (storage keys, disk and snapshot export) is covered by C10 in the cloud folder. Data-plane blob reads need storage diagnostic logging, which these rules do not assume.

| Rule | Behaviour |
|---|---|
| IN01 | Mass SharePoint/OneDrive download or sync by one user |
| IN02 | External or anonymous sharing at volume, or to personal webmail |
| IN03 | Confluence space export or bulk page export/view |
| IN04 | eDiscovery / content search export by a non-eDiscovery user |
| IN05 | Outbound mail to personal webmail with attachments at volume |
| IN06 | Mass file or site deletion (sabotage) |
| IN07 | Broad access across many sites the user does not own (snooping) |
| IN08 | After-hours bulk download |
| IN09 | SharePoint search for secrets followed by sensitive file access or bulk download |
