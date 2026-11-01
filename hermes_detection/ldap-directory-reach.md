# Directory reach — one process fanning out across directory servers (CrowdStrike FDR)

The only surviving view of LDAP collection in this estate. Windows logs it twice and neither is available: **4662** with the read-property/control-access masks would show *what* was read, but `0x10`/`0x100` are not being logged (probing returns only replication and write masks), and **1644** would show the search filter and `SDFlags`, but the Directory Service only emits it at NTDS diagnostics Level 5, which is not collected. That leaves network telemetry, which sees the one thing neither log could give: **which host and which process reached the directory, and how many servers it reached**.

```esql
FROM logs-yourorg-crowdstrike-data-default*
// 15-minute window in the query: the rule settings alone let an analyst reopen this over a week and turn
// it into a different rule.
| WHERE @timestamp >= NOW() - 15 minutes
// Outbound connections to directory services: LDAP, LDAPS, Global Catalog, ADWS.
  AND event.action IN ("networkconnectip4", "networkconnectip6")
  AND data.ConnectionDirection == "0"
  AND destination.port IN (389, 636, 3268, 3269, 9389)
// The CIDR test is a function on a field, so it is computed once after the gate rather than inside it.
// fc00::/7 is unique-local only - add your global prefix if the DCs hold global IPv6 addresses.
| EVAL internal_dest = CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
| WHERE internal_dest
// Fall back to the raw field: a null process.name would otherwise delete every kernel-attributed
// connection without a trace, which is most of the SMB-adjacent traffic a collector produces.
| EVAL proc = TO_LOWER(COALESCE(process.name, data.ContextBaseFileName, "unknown"))
// Netlogon's DC locator runs inside lsass and pings several DCs by design - that is discovery, not
// enumeration. LDAP issued through SSPI from inside lsass is invisible to this rule: a blind spot, not an
// exclusion, and the one an attacker who lives inside lsass would use.
| WHERE proc != "lsass.exe"
| STATS directory_servers = COUNT_DISTINCT(destination.ip),
        connections = COUNT(*),
        over_adws = MAX(CASE(destination.port == 9389, 1, 0)),
        ports_seen = MV_SLICE(VALUES(destination.port), 0, 5),
        servers_seen = MV_SLICE(VALUES(destination.ip), 0, 10),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.id, host.name, proc
// Two shapes, because the tools differ. A sweep reaches several DCs; a collector that pins one DC -
// which is what SharpHound and bloodhound.py mostly do - only shows up as many connections to it.
// 3 servers / 50 connections in 15 minutes are starting values: the baseline below is what sets them.
| WHERE directory_servers >= 3 OR connections >= 50
| EVAL finding = CASE(over_adws == 1, "directory_sweep_adws", "directory_reach")
| SORT connections DESC
| LIMIT 100
```

## Why this rule, and not the Windows one

The honest answer is that the better detection was available and is not any more. A 4662 rule keyed on the SD-read access masks observes **the act** - an account reading the security descriptor of object after object, which is exactly what BloodHound's ACL collection is - and it would name the account and the objects without depending on network topology. It cannot fire here because those masks are not written, and 1644 is off for a cost reason that is entirely reasonable (Level 5 on a busy DC is ten to fifty thousand events a second). So the choice was between nothing and a proxy.

The proxy earns its place because it answers a question no DC-side log can: **attribution**. 4662 has no client address at all, so an account reading three thousand ACLs is a name with no machine behind it; here every row is a host, a process and a destination set. For triage that is often the difference between an alert and a case. It also needs no audit configuration, so it works the day it is deployed, and it covers ADWS (9389), which is the endpoint SOAPHound uses specifically to avoid LDAP rules. And it is cheap: the index and fields are already in use by 72 rules in this library.

## The limitations, stated plainly

**It sees the reach, never the query.** No filter, no search base, no attribute list, no `SDFlags`, no entry counts. A bind, a paged search for one object and a whole-directory ACL dump look identical at the network layer - the only differences are how many connections and how much data, and data volume is not in this event. So the rule infers collection from *breadth*, which is a proxy, not evidence: a single-DC read of 3,000 objects with one connection is invisible, while fifty unrelated binds by a monitoring agent can look like a sweep.

**Attribution has its own hole.** ADWS queries reach LDAP through the DC's own web service, so the DC records the client as `::1` - loopback - and the real source is only recoverable by pairing a 5156 network event with the connection port, which this estate does not collect. An attacker who goes over ADWS therefore gets a rule that fires with an unusable address. That is precisely why the `finding` label separates `directory_sweep_adws` from the rest: the alert is telling you the attribution is weak, not that it is wrong.

**Only managed hosts exist.** The sensor is on the endpoint, so a collector run from an unmanaged laptop, a Linux attack box or a device behind a proxy produces nothing here - and the pearl of this technique (ADExplorer from a signed tool on a contractor's machine) is exactly the case that disappears. The DC-side log would have seen it; this rule cannot.

**Encryption and evasion are out of scope.** Pinned TLS, DoH-wrapped lookups, and anything that never opens 389/636/3268/3269/9389 through the sensor is invisible. Double-clicking: the port list is the whole detection surface, so a collector on a non-standard directory port walks straight past it.

**lsass is excluded, and that is a real gap.** The exclusion is necessary - the DC locator pings every DC in the estate by design - but it also hides anything issued through SSPI from inside lsass. Neither the exclusion nor the gap is avoidable without a second source.

## What would let us go back
Either of these restores the direct view, and the 4662 rule in `ldap-security-descriptor-enumeration.md` is kept for that day:
1. **Widen the SACL** so that *Read Property* on `nTSecurityDescriptor` is audited on the domain NC - then the `0x10`/`0x100` masks appear and the 4662 rule works with no threshold guesswork.
2. **Raise NTDS diagnostics to Level 5** with a tuned expensive-search threshold for a bounded hunt window - then 1644 returns the filter and `SDFlags`, which is the most precise signal of the three.

## Probes — how the two Windows losses were confirmed

Neither loss is an assumption: both are one query away, and the rule's whole shape depends on them. Re-run after any audit-policy change.

**4662: which access masks are actually written?** Read property is `0x10`, control access is `0x100` - the two rights that cover reading an object's security descriptor. If neither appears, nothing audits SD reads regardless of what the SACL looks like.

```esql
FROM logs-yourorg-microsoft-windows*
| WHERE @timestamp >= NOW() - 24 hours
  AND event.code == "4662"
| STATS events = COUNT(*), last = MAX(@timestamp) BY winevt.event_data.access_mask
| SORT events DESC
| LIMIT 25
```
A healthy ACL-enumeration feed shows `0x10` and `0x100` carrying most of the volume on directory objects. This estate returns only the write-side masks (add/delete/write-property), which is why the 4662 rule in `ldap-security-descriptor-enumeration.md` cannot fire. Follow-up worth running at the same time: if `0x100` is genuinely absent, any DCSync rule that requires control access is also matching nothing - check I01's gate against this same output.

**1644: is Directory Service diagnostic logging on?** The event only exists at NTDS diagnostics Level 5, so absence is the expected answer.

```esql
FROM logs-yourorg-microsoft-windows*
| WHERE @timestamp >= NOW() - 7 days
  AND event.code == "1644"
| STATS n = COUNT(*) BY host.name
| SORT n DESC
```
Empty = Level 5 is off on every DC, so no rule can key on the search filter or `SDFlags`. That is the single most valuable missing signal here; it is also the most expensive to enable.

## Verify before enabling
- Confirm both directions land as assumed - `ConnectionDirection`, and the ports in ECS rather than the raw `LocalPort`/`RemotePort`:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action IN ("networkconnectip4", "networkconnectip6")
| STATS n = COUNT(*) BY event.action, data.ConnectionDirection
| SORT n DESC
```
If `data.ConnectionDirection` ingests numeric, the `"0"` comparison returns nothing and the rule is silently dead - that is the first thing to check.
- Baseline which processes legitimately reach several DCs in your estate (management tools, Entra Connect, monitoring) before trusting the server count:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 7 days
  AND event.action IN ("networkconnectip4", "networkconnectip6")
  AND data.ConnectionDirection == "0"
  AND destination.port IN (389, 636, 3268, 3269, 9389)
| EVAL proc = TO_LOWER(COALESCE(process.name, data.ContextBaseFileName, "unknown"))
| STATS servers = COUNT_DISTINCT(destination.ip), connections = COUNT(*) BY host.name, proc
| SORT servers DESC
| LIMIT 50
```

## References
- `ldap-security-descriptor-enumeration.md` - the 4662 rule this replaces, blocked on unlogged access masks
- `rules/05-identity/I01` - DCSync on the same 4662 stream; the replication GUIDs are excluded here so the two do not overlap
- Schwartz, *From Code to Coverage* (TROOPERS26) - why 1644 is the precise signal, what Level 5 costs, and the ADWS `[::1]` attribution problem: `troopers.de/downloads/troopers26/TR26_From_Code_to_Coverage_TPGLJU.pdf`
- Elastic Zscaler/FDR field conventions in `docs/ESQL-CONVENTIONS.md` - `event.action` lowercase, raw fields under `data.*`
