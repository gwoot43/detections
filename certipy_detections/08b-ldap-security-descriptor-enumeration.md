---
id: LDAPSD-01
name: LDAP security-descriptor enumeration - a client reading ACLs object by object, seen in Directory Service 1644
language: esql
index: logs-yourorg-microsoft-windows*
mitre: [T1087.002, T1069.002]
data_source: Directory Service channel 1644 (NTDS diagnostic logging raised)
suppression:
  fields: [client_ip]
  duration: 6h
  missing_fields: do_not_suppress
---
**Catches the read itself.** BloodHound-class collection ends in one thing: asking the directory for the **security descriptor** of many objects, because that is where the ACL edges are. An LDAP client does that with the `LDAP_SERVER_SD_FLAGS_OID` control (`1.2.840.113556.1.4.801`), whose flags are `OWNER 0x1`, `GROUP 0x2`, `DACL 0x4`, `SACL 0x8`. A collector asks for owner, group and DACL and skips the SACL - `0x4`, `0x5` or `0x7` - because the SACL is not an edge in the graph.

When the DC's Directory Service logging is raised, a search that crosses its "expensive search" threshold is written as **1644**, and the message carries the parts that matter: the **SDFlags** the client asked for, the filter, and the client address. Huntress documented this exact signature - SharpHound's group enumeration appearing in 1644 with `SDFlags: 0x5`. That makes the SD-flagged search the closest thing to a direct observation of ACL collection: no fan-out needed, no threshold gymnastics, and it works when the collector queries a single DC.

It is the companion to **08**, not a duplicate of it: 08 sees the SMB side of a session/local-admin sweep, this sees the directory side, including `-c DCOnly` and `bloodhound.py`, which open no pipe at all. **24** covers the network fan-out across DCs.

## Field reality
- The event body is **free text**, so the whole rule is two `GROK`s over the message: one for `SDFlags`, one for the client address. There is no `event_data` on this provider, so `winevt.event_data.*` is empty here - the text lands in ECS **`message`**. Confirm with the probe below before trusting the field.
- The **client address** label differs by Windows version and by whether the search came over LDAP or ADWS: `Visitor address:` on some builds, `Client:` on others. The pattern accepts either; if your samples show a third form, change the one alternative.
- **The account is not in the event.** 1644 names the client address, not the identity that bound. Attribution is a pivot (4624/4768 from that address, or the Falcon query at the end), so the alert carries `client_ip` and leaves the account to triage.

## Query
```esql
FROM logs-yourorg-microsoft-windows*
// 1644 = the Directory Service logged an expensive search. Only emitted when NTDS diagnostic logging is raised.
| WHERE event.code == "1644"
// The filter is the message text: is this a search that asked for security descriptors at all?
| GROK message """(?i)SDFlags:\s*(?<sdflags>0x[0-9a-f]+)"""
| WHERE sdflags IS NOT NULL
| EVAL sdflags = TO_LOWER(sdflags)
// 0x4 DACL, 0x5 OWNER+DACL, 0x7 OWNER+GROUP+DACL - "everything except the SACL", which is what an ACL
// collector asks for. 0x8 (SACL) or 0x1/0x2 alone are not the enumeration shape.
| WHERE sdflags IN ("0x4", "0x5", "0x7")
// The client address, from whichever label this build writes.
| GROK message """(?i)(?:Visitor address|Client(?: address)?)[:\s]+(?<client_ip>[0-9a-fA-F.:]{7,45})"""
| EVAL client_ip = COALESCE(client_ip, "unknown-client")
// What was asked for, bounded: the filter shape is the triage detail, the base says which naming context.
| GROK message """(?i)Search Filter:\s*(?<ldap_filter>.{1,80})"""
| STATS searches = COUNT(*),
        sdflags_seen = MV_SLICE(VALUES(sdflags), 0, 4),
        filters = MV_SLICE(VALUES(ldap_filter), 0, 5),
        dcs = COUNT_DISTINCT(host.name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY client_ip
// 3 SD-flagged searches from one client in the window is a starting value: a person reading one object's
// permissions produces one, a collector walks the directory. Replace it with the p99 from the Baseline.
| WHERE searches >= 3
// One object read is a person looking; the same client reading ACROSS DCs is collection in progress.
| EVAL pattern = CASE(dcs >= 2, "collector across DCs", "single-DC reads")
| SORT searches DESC
| LIMIT 100
```
`sdflags_seen` tells the analyst whether the tool wanted DACLs only (`0x4`) or owner and group as well (`0x7`) - the latter is graph collection, and `filters` usually shows an `(objectClass=*)`-style walk rather than one named object.

## Baseline
Over 7 days at the rule's window. Percentiles over active buckets only - a quarter hour with no such search produces no row.
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE event.code == "1644"
| GROK message """(?i)SDFlags:\s*(?<sdflags>0x[0-9a-f]+)"""
| WHERE sdflags IS NOT NULL
| EVAL sdflags = TO_LOWER(sdflags)
| WHERE sdflags IN ("0x4", "0x5", "0x7")
| GROK message """(?i)(?:Visitor address|Client(?: address)?)[:\s]+(?<client_ip>[0-9a-fA-F.:]{7,45})"""
| EVAL client_ip = COALESCE(client_ip, "unknown-client"),
       bucket = DATE_TRUNC(15 minutes, @timestamp)
| STATS searches = COUNT(*) BY client_ip, bucket
// this is the baseline: no threshold here, because filtering first would hide the clients the rule must clear
| STATS active_buckets = COUNT(*), p50 = PERCENTILE(searches, 50), p99 = PERCENTILE(searches, 99),
        peak = MAX(searches), hot_buckets = COUNT(*) WHERE searches >= 3
    BY client_ip
| SORT peak DESC
| LIMIT 50
```
A `peak` of 1-2 per quarter hour is a person or a tool looking at one object. `peak` in the hundreds is a directory walk: identify the address, then exclude it as a known auditor (PingCastle, Purple Knight, a backup tool reading permissions) by address **and** by the account that owns it.

## Before turning it on
- **1644 only exists when NTDS diagnostic logging is raised** - Microsoft treats that level as troubleshooting-grade: high volume in the Directory Service log and not something to leave on indefinitely. Confirm the level your DCs run at, and treat this as a rule you switch on for a hunt window, or accept the log cost deliberately. [C] The exact level that emits 1644 is version-specific; check it against your DCs rather than trusting a number from a blog.
- **Collect the Directory Service channel.** The Windows integration does not read it by default; it needs its own event log input in the agent policy.
- Settle the two field assumptions with real samples before deploying:
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE event.code == "1644"
| KEEP @timestamp, host.name, message
| LIMIT 5
```
  Read from that: the exact `SDFlags:` spelling, the client-address label, and whether the text is in `message` (ECS) or somewhere else in your pipeline.
- Confirm the events arrive from the DCs and not from member servers (1644 is also used by other components - if your estate shows it from elsewhere, add a provider or host filter).
- Attend the volume: if `searches >= 3` fires on the DC's own maintenance, raise the threshold from the baseline rather than excluding the DC.

## What it misses
- **Directory reads that never cross the expensive-search threshold.** A collector that pages its queries politely, one object at a time, produces no 1644 at all - this rule is only as good as the logging level, which is its main weakness. 24 (network fan-out) and 08 (SMB side) stay on regardless.
- **ADWS / SOAPHound.** A collector using the AD Web Services endpoint (9389) may not surface as an LDAP search at all; 24 flags `directory_sweep_adws` for exactly this reason.
- **Tools that read one ACL at a time** across a long period - the volume-based threshold is the wrong shape for that; it becomes a rarity problem per client and per day.
- **The identity behind the read.** 1644 carries the address, not the account, so an attacker on a shared jump host is attributed to that host until the pivot is run.
- **Non-ACL collection.** Group membership, sessions and trusts do not all require an SD read; those show in 08 (SMB) and in the DC's own 4662/4769 traffic.

## When it fires
1. Identify `client_ip`: managed host, jump box, or unknown. Unknown means the attacker's own machine or a proxy - check 05 on the hosts around it.
2. Get the account: the DC's own logon records for that address are the fastest attribution.
```esql
FROM logs-yourorg-microsoft-windows*
// who authenticated from the alert's address around the alert window
| WHERE event.code IN ("4624", "4768") AND source.ip == "<client_ip>"
| STATS n = COUNT(*) BY user.name, event.code
| SORT n DESC
| LIMIT 20
```
3. Read `sdflags_seen` and `filters` from the alert: `0x7` plus a broad filter is the graph-building shape, `0x4` on a handful of named objects is more likely an admin checking permissions.
4. Then name the binary with the Falcon pivot in 08, restricted to the directory ports (389/636/3268/3269/9389); `sharphound.exe`, `powershell.exe`, `SharpHound.exe` or an unknown binary on those ports is the collector.
