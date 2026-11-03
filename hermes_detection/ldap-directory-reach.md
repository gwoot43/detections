# Directory reach — one process fanning out across directory servers (CrowdStrike FDR)

The only surviving view of LDAP collection in this estate. Windows logs it twice and neither is available: **4662** with the read-property/control-access masks would show *what* was read, but `0x10`/`0x100` are not being logged (probing returns only replication and write masks), and **1644** would show the search filter and `SDFlags`, but the Directory Service only emits it at NTDS diagnostics Level 5, which is not collected. That leaves network telemetry, which sees the one thing neither log could give: **which host and which process reached the directory, and how many servers it reached**.

Directory fan-out is the signal: one process reaching many domain controllers over LDAP in a short window is either a management tool (a known, excludable set) or a collector. The rule excludes the estate's heavy hitters by identity and alerts on the rest crossing a breadth threshold. Below: a **deployable** ES|QL variant (run with a 2-hour lookback), a **bucketed** ES|QL variant (one row per 2-hour window, for replaying against live data), and a **LogScale/CQL** version of the bucket. `9389` (ADWS) is split into `adws-directory-access.md`.

### Deployable (ES|QL, 2-hour lookback)
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Deploy with the rule's lookback set to 2 hours: the window is the schedule, there is no bucket.
| WHERE @timestamp >= NOW() - 2 hours
  AND event.action IN ("networkconnectip4", "networkconnectip6")
  AND data.ConnectionDirection == "0"
  AND data.event_platform == "Win"                 // Linux sssd/winbind fail over across DCs by design
  AND destination.port IN (389, 636, 3268, 3269)
// CIDR is a function on a field, so compute it once after the gate, not inside it. fc00::/7 is unique-local;
// add your global IPv6 prefix if the DCs hold one.
| EVAL internal_dest = CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
| WHERE internal_dest
// Base file name, falling back to the kernel-attributed name, so a renamed or kernel-issued collector is kept.
| EVAL proc = TO_LOWER(COALESCE(process.name, data.ContextBaseFileName, "unknown"))
// Estate-wide heavy hitters, excluded by identity (not by muting a technique). lsass = Netlogon DC locator
// (normal discovery); the rest are the management tools that legitimately sweep DCs. Host-scoped exceptions
// belong in the central exception list.
| WHERE proc NOT IN ("lsass.exe", "microsoft.tri.sensor.exe", "shdelegator.exe",
                     "microsoft.identity.health.agentv15.service.exe",
                     "microsoft.identity.health.adds.insightsservice.exe",
                     "microsoft.exchange.directory.topologyservice.exe",
                     "citrix.configurationlogging.exe")
  AND proc != "unknown"
| STATS directory_servers = COUNT_DISTINCT(destination.ip),
        connections = COUNT(*),
        destination.port = VALUES(destination.port),
        servers_seen = MV_SLICE(VALUES(destination.ip), 0, 19),
        host.name = VALUES(host.name),
        event.start = MIN(@timestamp), event.end = MAX(@timestamp)
    BY host.id, process.name = proc
// source: 30-day replay - benign maximum 15 DCs (repadmin / SCCM / Citrix broker, excepted); an internal
// pentest sweep reached 62. 12 sits between them. Baseline below.
| WHERE directory_servers >= 12
| SORT directory_servers DESC
| LIMIT 100
```
Deploy every 2 hours over the last 2 hours. Suppress by `host.id` + `process.name` for 24h.

### Bucketed (ES|QL, 2-hour windows — for live testing)
Same logic, but a `DATE_TRUNC` bucket instead of a lookback, so you can run it across a long range and read each 2-hour window on its own. The time picker bounds the scan.
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action IN ("networkconnectip4", "networkconnectip6")
  AND data.ConnectionDirection == "0"
  AND data.event_platform == "Win"
  AND destination.port IN (389, 636, 3268, 3269)
| EVAL internal_dest = CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"),
       time_bucket = DATE_TRUNC(2 hours, @timestamp)
| WHERE internal_dest
| EVAL proc = TO_LOWER(COALESCE(process.name, data.ContextBaseFileName, "unknown"))
| WHERE proc NOT IN ("lsass.exe", "microsoft.tri.sensor.exe", "shdelegator.exe",
                     "microsoft.identity.health.agentv15.service.exe",
                     "microsoft.identity.health.adds.insightsservice.exe",
                     "microsoft.exchange.directory.topologyservice.exe",
                     "citrix.configurationlogging.exe")
  AND proc != "unknown"
| STATS directory_servers = COUNT_DISTINCT(destination.ip),
        connections = COUNT(*),
        destination.port = VALUES(destination.port),
        servers_seen = MV_SLICE(VALUES(destination.ip), 0, 19),
        host.name = VALUES(host.name),
        event.start = MIN(@timestamp), event.end = MAX(@timestamp)
    BY time_bucket, host.id, process.name = proc
// source: as above - 30-day replay, benign max 15 DCs, pentest reached 62.
| WHERE directory_servers >= 12
| SORT time_bucket DESC
| LIMIT 100
```

### LogScale (CQL, bucketed)
NetworkConnect events carry no image name, so attach it from ProcessRollup2 on the same host and process id (`defineTable` + `match`, the LogScale idiom for correlating two event types). 2-hour buckets. Confirm the field names (`RemotePort`, `ConnectionDirection`, `RemoteAddressIP4`, `ContextProcessId`, `TargetProcessId`, `event_platform`) against your LogScale repo before trusting it.
```logscale
#event_simpleName=/^NetworkConnect(IP4|IP6)$/
| ConnectionDirection="0"
| event_platform="Win"
| in(RemotePort, values=["389", "636", "3268", "3269"])
| cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
// attach the image name from ProcessRollup2 by aid + process id
| defineTable(name="procs", include=[aid, TargetProcessId, ImageFileName],
    query={#event_simpleName=/ProcessRollup2$/})
| match(table="procs", field=[aid, ContextProcessId], column=[aid, TargetProcessId], include=[ImageFileName], strict=true)
| proc := lower(ImageFileName)
| !in(proc, values=["*\\lsass.exe", "*\\microsoft.tri.sensor.exe", "*\\shdelegator.exe",
    "*\\microsoft.identity.health.agentv15.service.exe", "*\\microsoft.identity.health.adds.insightsservice.exe",
    "*\\microsoft.exchange.directory.topologyservice.exe", "*\\citrix.configurationlogging.exe"])
| bucket(span=2h, field=@timestamp)
| groupBy([_bucket, aid, proc],
    function=[count(RemoteAddressIP4, distinct=true, as=directory_servers), count(as=connections),
              collect([ComputerName])], limit=max)
// source: 30-day replay - benign max 15 DCs; an internal pentest sweep reached 62
| directory_servers >= 12
| sort(directory_servers, order=desc, limit=100)
```

## Why this rule, and not the Windows one

The honest answer is that the better detection was available and is not any more. A 4662 rule keyed on the SD-read access masks observes **the act** - an account reading the security descriptor of object after object, which is exactly what BloodHound's ACL collection is - and it would name the account and the objects without depending on network topology. It cannot fire here because those masks are not written, and 1644 is off for a cost reason that is entirely reasonable (Level 5 on a busy DC is ten to fifty thousand events a second). So the choice was between nothing and a proxy.

The proxy earns its place because it answers a question no DC-side log can: **attribution**. 4662 has no client address at all, so an account reading three thousand ACLs is a name with no machine behind it; here every row is a host, a process and a destination set. For triage that is often the difference between an alert and a case. It also needs no audit configuration, so it works the day it is deployed. (ADWS - 9389, the endpoint SOAPHound uses specifically to avoid LDAP rules - is split into its own rule, `adws-directory-access.md`, because its legitimate client set and its `::1` attribution hole both differ from plain LDAP.) And it is cheap: the index and fields are already in use by other rules in this library.

## The limitations, stated plainly

**It sees the reach, never the query.** No filter, no search base, no attribute list, no `SDFlags`, no entry counts. A bind, a paged search for one object and a whole-directory ACL dump look identical at the network layer - the only differences are how many connections and how much data, and data volume is not in this event. So the rule infers collection from *breadth*, which is a proxy, not evidence: a single-DC read of 3,000 objects with one connection is invisible, while fifty unrelated binds by a monitoring agent can look like a sweep.

**ADWS is handled separately.** 9389 (AD Web Services, SOAPHound's way around LDAP rules) is in `adws-directory-access.md`. It has a different legitimate client set, and the DC records ADWS clients as `::1` - loopback - so its attribution is weak in a way 389/636/3268/3269 are not. This rule's attribution, by contrast, is solid: every row is a host and a process.

**Only managed hosts exist.** The sensor is on the endpoint, so a collector run from an unmanaged laptop, a Linux attack box or a device behind a proxy produces nothing here - and the pearl of this technique (ADExplorer from a signed tool on a contractor's machine) is exactly the case that disappears. The DC-side log would have seen it; this rule cannot.

**Encryption and evasion are out of scope.** Pinned TLS, DoH-wrapped lookups, and anything that never opens 389/636/3268/3269 through the sensor is invisible. Double-clicking: the port list is the whole detection surface, so a collector on a non-standard directory port walks straight past it.

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
- Baseline which processes legitimately reach several DCs before trusting the threshold - run the deployable query above over 30 days with the `directory_servers >= 12` line removed and `BY process.name = proc` only, and read the top of the list: those are the estate's management tools (the excluded set), and the gap between them and a collector is where the floor sits.

## References
- `ldap-security-descriptor-enumeration.md` - the 4662 rule this replaces, blocked on unlogged access masks
- `rules/05-identity/I01` - DCSync on the same 4662 stream; the replication GUIDs are excluded here so the two do not overlap
- Schwartz, *From Code to Coverage* (TROOPERS26) - why 1644 is the precise signal, what Level 5 costs, and the ADWS `[::1]` attribution problem: `troopers.de/downloads/troopers26/TR26_From_Code_to_Coverage_TPGLJU.pdf`
- Elastic Zscaler/FDR field conventions in `docs/ESQL-CONVENTIONS.md` - `event.action` lowercase, raw fields under `data.*`
