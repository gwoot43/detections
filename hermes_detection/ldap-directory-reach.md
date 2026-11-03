# Directory reach — one process fanning out across directory servers (CrowdStrike FDR)

The only surviving view of LDAP collection in this estate. Windows logs it twice and neither is available: **4662** with the read-property/control-access masks would show *what* was read, but `0x10`/`0x100` are not being logged (probing returns only replication and write masks), and **1644** would show the search filter and `SDFlags`, but the Directory Service only emits it at NTDS diagnostics Level 5, which is not collected. That leaves network telemetry, which sees the one thing neither log could give: **which host and which process reached the directory, and how many servers it reached**.

The anchor is **novelty, not a maintained exception list**: a process that has never reached a directory server in the trailing 30 days, suddenly fanning out, is the signal. A renamed or unknown collector (SOAPHound, a one-off `code.exe`) is new by construction - which is the case a denylist of agent names can never cover - while a sanctioned client, even a freshly patched one, is already in the baseline and never fires. The 30-day history is **not** scanned on every run (that would be the expensive part); it lives in a lookup index refreshed once a night by the builder below, so the live rule is a short-window read plus a join.

```esql
FROM logs-yourorg-crowdstrike-data-default*
// 15-minute window: the hot path reads only this. The 30-day baseline it joins against is precomputed, so
// the run never pays for the lookback.
| WHERE @timestamp >= NOW() - 15 minutes
// Outbound connections to directory services: LDAP, LDAPS, Global Catalog. ADWS (9389) is its own rule,
// adws-directory-access.md, because its legitimate client set and its attribution hole are both different.
  AND event.action IN ("networkconnectip4", "networkconnectip6")
  AND data.ConnectionDirection == "0"
  AND data.event_platform == "Win"                 // Linux sssd/winbind fail over across DCs by design
  AND destination.port IN (389, 636, 3268, 3269)
// CIDR is a function on a field, so compute it once after the gate, not inside it. fc00::/7 is unique-local;
// add your global IPv6 prefix if the DCs hold one.
| EVAL internal_dest = CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
| WHERE internal_dest
// Key on the base file name, falling back to the kernel-attributed name, so a renamed or kernel-issued
// collector is not lost. lsass is the Netlogon DC locator (and SSPI-issued LDAP) - it reaches every DC by
// design and is a deliberate blind spot, so it is the one name kept inline rather than in the baseline.
| EVAL proc = TO_LOWER(COALESCE(process.name, data.ContextBaseFileName, "unknown"))
| WHERE proc != "lsass.exe" AND proc != "unknown"
| STATS directory_servers = COUNT_DISTINCT(destination.ip),
        connections = COUNT(*),
        hosts = COUNT_DISTINCT(host.id),
        servers_seen = MV_SLICE(VALUES(destination.ip), 0, 10),
        host_names = MV_SLICE(VALUES(host.name), 0, 5),
        event.start = MIN(@timestamp), event.end = MAX(@timestamp)
    BY proc
// Novelty: keep only processes NOT in the 30-day baseline - never seen reaching a DC in the estate. This is
// the exception list, self-maintaining: a version-stamped agent name never has to be added, and the tool the
// list has not heard of is caught because it is new, not because it is named.
| LOOKUP JOIN directory_client_baseline ON proc
| WHERE baseline_first_seen IS NULL
// Fleet rarity is the partner: a genuine new rollout is novel too, but lands on many hosts at once, so
// hosts <= 2 drops it while a collector on one box fires. directory_servers >= 12 keeps it a fan-out.
// source: 30-day replay, benign max 15 DCs (repadmin / SCCM / Citrix broker, all in the baseline); an
// internal pentest sweep reached 62.
  AND directory_servers >= 12 AND hosts <= 2
| SORT directory_servers DESC
| LIMIT 100
```

## Baseline — build the lookup nightly, not per run
This is the only place the 30-day window is read. Run it once a night and write the result to the `directory_client_baseline` lookup index, or (cheaper) maintain that index with an Elastic **transform**, which updates incrementally and never full-scans. Either way the live rule above only ever does a short read plus the join.
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 30 days
  AND event.action IN ("networkconnectip4", "networkconnectip6")
  AND data.ConnectionDirection == "0"
  AND data.event_platform == "Win"
  AND destination.port IN (389, 636, 3268, 3269)
| EVAL internal_dest = CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
| WHERE internal_dest
| EVAL proc = TO_LOWER(COALESCE(process.name, data.ContextBaseFileName, "unknown"))
// one row per process: the estate's known directory clients, keyed on proc for the LOOKUP JOIN above
| STATS baseline_first_seen = MIN(@timestamp), baseline_last_seen = MAX(@timestamp),
        baseline_hosts = COUNT_DISTINCT(host.id), baseline_servers = COUNT_DISTINCT(destination.ip)
    BY proc
```
Read the top of this (sort by `baseline_servers`) before trusting the live rule: the heavy-hitters are the estate's own management tools, and they are exactly the population the old maintained exception list was trying - and failing - to keep current.

## If you have no lookup index yet
Interim, no baseline required, so it loses the novelty discriminator and leans on breadth plus fleet rarity, with `lsass` kept inline. Noisier - run it as a hunt, with a higher floor, until the baseline exists:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 4 hours
  AND event.action IN ("networkconnectip4", "networkconnectip6")
  AND data.ConnectionDirection == "0"
  AND data.event_platform == "Win"
  AND destination.port IN (389, 636, 3268, 3269)
| EVAL internal_dest = CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
| WHERE internal_dest
| EVAL proc = TO_LOWER(COALESCE(process.name, data.ContextBaseFileName, "unknown"))
| WHERE proc != "lsass.exe" AND proc != "unknown"
| STATS directory_servers = COUNT_DISTINCT(destination.ip), connections = COUNT(*),
        hosts = COUNT_DISTINCT(host.id), servers_seen = MV_SLICE(VALUES(destination.ip), 0, 10),
        host_names = MV_SLICE(VALUES(host.name), 0, 5), event.start = MIN(@timestamp), event.end = MAX(@timestamp)
    BY proc
// Higher floor than the novelty rule, because without the baseline breadth is the only discriminator left.
// source: 30-day replay benign max 15 DCs; the pentest sweep reached 62.
| WHERE directory_servers >= 16 AND hosts <= 2
| SORT directory_servers DESC
| LIMIT 100
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
- The process baseline is now the **nightly builder** above (`directory_client_baseline`); read its top rows (sort by `baseline_servers`) to see which processes legitimately reach several DCs - management tools, Entra Connect, monitoring - before trusting the live rule.

## References
- `ldap-security-descriptor-enumeration.md` - the 4662 rule this replaces, blocked on unlogged access masks
- `rules/05-identity/I01` - DCSync on the same 4662 stream; the replication GUIDs are excluded here so the two do not overlap
- Schwartz, *From Code to Coverage* (TROOPERS26) - why 1644 is the precise signal, what Level 5 costs, and the ADWS `[::1]` attribution problem: `troopers.de/downloads/troopers26/TR26_From_Code_to_Coverage_TPGLJU.pdf`
- Elastic Zscaler/FDR field conventions in `docs/ESQL-CONVENTIONS.md` - `event.action` lowercase, raw fields under `data.*`
