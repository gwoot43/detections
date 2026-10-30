# LDAP security-descriptor enumeration

BloodHound-class collection ends by asking the directory for the **security descriptor** of many objects, using the `LDAP_SERVER_SD_FLAGS_OID` control - `OWNER 0x1`, `GROUP 0x2`, `DACL 0x4`, `SACL 0x8` - so `0x4`, `0x5` or `0x7` means "owner, group and DACL, no SACL", which is exactly what an ACL collector needs (Huntress documented SharpHound's group enumeration arriving in 1644 at `SDFlags: 0x5`). When NTDS diagnostic logging is raised, a search that crosses the expensive-search threshold is written as Directory Service **1644**, and the message text carries the `SDFlags`, the search filter and the client address - the closest thing to a direct observation of ACL collection, and the only view of `-c DCOnly`, `bloodhound.py` and ADExplorer, which open no SMB pipe at all. Three or more SD-flagged searches from one client in the window is the starting threshold: a person opening one object's permissions produces one, a collector walks the directory. Two caveats: 1644 carries **no account**, so attribution is a pivot on the client address (4624/4768 from that IP), and it is only emitted when that diagnostics logging is on - troubleshooting-grade volume, so a hunt-window rule unless you accept the cost. 4662 with *Audit Directory Service Access* is the other DC-side view, but only for objects carrying a SACL - test a known SD read before switching. Run every 15 minutes over the last 15; suppress by `client_ip` for 6h.

```esql
FROM logs-yourorg-microsoft-windows*
// 1644 = the Directory Service logged an expensive search. Only emitted when NTDS diagnostic logging is raised.
| WHERE event.code == "1644"
// The event body is free text: is this a search that asked for security descriptors at all?
| GROK message """(?i)SDFlags:\s*(?<sdflags>0x[0-9a-f]+)"""
| WHERE sdflags IS NOT NULL
| EVAL sdflags = TO_LOWER(sdflags)
// 0x4 DACL, 0x5 OWNER+DACL, 0x7 OWNER+GROUP+DACL - "everything except the SACL", which is what an ACL
// collector asks for. 0x8 (SACL) or 0x1/0x2 alone are not the enumeration shape.
| WHERE sdflags IN ("0x4", "0x5", "0x7")
// The client address, from whichever label this build writes.
| GROK message """(?i)(?:Visitor address|Client(?: address)?)[:\s]+(?<client_ip>[0-9a-fA-F.:]{7,45})"""
| EVAL client_ip = COALESCE(client_ip, "unknown-client")
// What was asked for, bounded: the filter shape is the triage detail.
| GROK message """(?i)Search Filter:\s*(?<ldap_filter>.{1,80})"""
| STATS searches = COUNT(*),
        sdflags_seen = MV_SLICE(VALUES(sdflags), 0, 4),
        filters = MV_SLICE(VALUES(ldap_filter), 0, 5),
        dcs = COUNT_DISTINCT(host.name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY client_ip
// 3 SD-flagged searches from one client in the window is a starting value - measure your own p99.
| WHERE searches >= 3
| SORT searches DESC
| LIMIT 100
```

Verify the two message patterns against a real sample first: `FROM logs-yourorg-microsoft-windows* | WHERE event.code == "1644" | KEEP @timestamp, host.name, message | LIMIT 5` - the client label differs by build (`Visitor address:` on some, `Client:` on others) and the text may sit in a pipeline-specific field rather than ECS `message`.
