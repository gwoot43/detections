# ADWS directory access — a new client on 9389 (SOAPHound-class)

AD Web Services (**TCP 9389**) answers the same directory queries as LDAP, over SOAP. SOAPHound and SoaPy use it **specifically to avoid LDAP rules**: the collection that would light up 389/636 instead rides 9389, where most estates are not looking. The legitimate client set is small and stable - the AD PowerShell module (`powershell.exe`, `pwsh.exe`, `powershell_ise.exe`), WinRM remoting (`wsmprovhost.exe`), the AD Administrative Center (`dsac.exe`) - so a process **new to ADWS** is the signal, not any particular name.

Like `ldap-directory-reach.md`, this anchors on **novelty against a 30-day baseline**, not a maintained allowlist: a process that has never spoken ADWS in the estate in 30 days, reaching directory servers now, is SOAPHound-class by construction. The 30-day history is precomputed nightly (the builder below), so the live rule is a short-window read plus a join.

```esql
FROM logs-yourorg-crowdstrike-data-default*
// 4-hour window: ADWS collection is bursty and low-volume, so a slightly wider window than the LDAP rule
// carries the fan-out without scanning history - the baseline it joins is precomputed.
| WHERE @timestamp >= NOW() - 4 hours
  AND event.action IN ("networkconnectip4", "networkconnectip6")
  AND data.ConnectionDirection == "0"
  AND data.event_platform == "Win"
  AND destination.port == 9389
// CIDR is a function on a field, so compute it once after the gate. fc00::/7 is unique-local; add your
// global IPv6 prefix if the DCs hold one.
| EVAL internal_dest = CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
| WHERE internal_dest
// Base file name, falling back to the kernel-attributed name, so a renamed or kernel-issued client is kept.
| EVAL proc = TO_LOWER(COALESCE(process.name, data.ContextBaseFileName, "unknown"))
| WHERE proc != "unknown"
| STATS directory_servers = COUNT_DISTINCT(destination.ip),
        connections = COUNT(*),
        hosts = COUNT_DISTINCT(host.id),
        servers_seen = MV_SLICE(VALUES(destination.ip), 0, 10),
        host_names = MV_SLICE(VALUES(host.name), 0, 5),
        event.start = MIN(@timestamp), event.end = MAX(@timestamp)
    BY proc
| LOOKUP JOIN adws_client_baseline ON proc
// Two findings. A process new to ADWS in 30 days (not in the baseline) is the SOAPHound-class case - ADWS
// exists to answer LDAP without touching 389, so a new SOAP client is the whole signal, and fleet rarity
// (hosts <= 2) drops a genuine new rollout. A KNOWN client doing an abnormal volume is the second shape,
// kept because a compromised admin box can drive the sanctioned PowerShell AD module. source: 30-day replay -
// native clients sit at a handful of DCs; nothing benign reaches 6+ servers or 50+ connections over ADWS in
// four hours.
| EVAL finding = CASE(baseline_first_seen IS NULL, "adws_new_client", "adws_heavy_use")
| WHERE (baseline_first_seen IS NULL AND hosts <= 2)
     OR connections >= 50 OR directory_servers >= 6
| SORT directory_servers DESC
| LIMIT 100
```

Deploy every hour over the last 4 hours. Suppress by `proc` + `finding` for 24h.

## Baseline — build the lookup nightly
The only place the 30-day window is read. Run once a night into the `adws_client_baseline` lookup index, or maintain it with an Elastic **transform** (incremental, never full-scans):
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 30 days
  AND event.action IN ("networkconnectip4", "networkconnectip6")
  AND data.ConnectionDirection == "0"
  AND data.event_platform == "Win"
  AND destination.port == 9389
| EVAL internal_dest = CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
| WHERE internal_dest
| EVAL proc = TO_LOWER(COALESCE(process.name, data.ContextBaseFileName, "unknown"))
| STATS baseline_first_seen = MIN(@timestamp), baseline_last_seen = MAX(@timestamp),
        baseline_hosts = COUNT_DISTINCT(host.id), baseline_servers = COUNT_DISTINCT(destination.ip)
    BY proc
```
The rows should be a short list: the PowerShell AD module, `wsmprovhost.exe`, `dsac.exe`, maybe a monitoring agent. If it is longer than that, something already queries ADWS broadly and is worth understanding before you enable the live rule.

## If you have no lookup index yet
Interim, no baseline. Falls back to the stable native-client allowlist plus volume - weaker than novelty (a renamed collector that impersonates a native name slips it), so run it as a hunt until the baseline exists:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 4 hours
  AND event.action IN ("networkconnectip4", "networkconnectip6")
  AND data.ConnectionDirection == "0"
  AND data.event_platform == "Win"
  AND destination.port == 9389
| EVAL internal_dest = CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
| WHERE internal_dest
| EVAL proc = TO_LOWER(COALESCE(process.name, data.ContextBaseFileName, "unknown")),
       native = proc IN ("powershell.exe", "powershell_ise.exe", "pwsh.exe", "wsmprovhost.exe", "dsac.exe")
| WHERE proc != "unknown"
| STATS directory_servers = COUNT_DISTINCT(destination.ip), connections = COUNT(*),
        hosts = COUNT_DISTINCT(host.id), servers_seen = MV_SLICE(VALUES(destination.ip), 0, 10),
        host_names = MV_SLICE(VALUES(host.name), 0, 5), native = MAX(CASE(native, 1, 0)),
        event.start = MIN(@timestamp), event.end = MAX(@timestamp)
    BY proc
// A non-native client on ADWS at all, or a native one at abnormal volume. source: 30-day replay as above.
| WHERE (native == 0 AND hosts <= 2) OR connections >= 50 OR directory_servers >= 6
| EVAL finding = CASE(native == 0, "adws_unusual_client", "adws_heavy_use")
| SORT directory_servers DESC
| LIMIT 100
```

## Reading the alert
- **`finding = adws_new_client`** (or `adws_unusual_client` on the fallback) is the one to run down: a process that has never spoken ADWS, now reaching directory servers. If `proc` is **not** one of `powershell*`/`pwsh`/`wsmprovhost`/`dsac` it is near-certain SOAPHound-class; if it *is* a PowerShell name it is more likely a first-time admin task on a new box - check the host.
- **`host_names`** is the box to isolate. ADWS records the DC-side client as `::1`, so the endpoint sensor is the only place the real source exists - which is exactly why this rule is on FDR network telemetry, not a DC log.
- **`directory_servers`** is the fan-out; **`connections`** the depth. SoaPy/SOAPHound pulling the whole directory shows as many connections, often to one or two DCs.
- **`finding = adws_heavy_use`** is a known client at abnormal volume - triage, not a confirmed intrusion; usually a legitimate admin script, occasionally a driven one.

## Nearest benign twins
- **The AD PowerShell module / AD Administrative Center** run by an admin. Native, and in the baseline after the first 30 days - they never reach the `adws_new_client` branch, and `adws_heavy_use` only fires if one suddenly sweeps many DCs.
- **A monitoring or identity-governance product** that reads AD over ADWS. It will be in the baseline; if it is new, it lands on many hosts (a rollout), which `hosts <= 2` drops.
- **A first-time admin task** from a PowerShell console on a box that has not done it before. Novel, so it fires once - the `proc` being a PowerShell name is the tell, and it is an entity pair after review.

## What it misses
- **A collector that impersonates a native name** (drops `powershell.exe` into a path and runs from it). Novelty still catches it if that exact `proc`+behaviour is new to ADWS; the fallback's allowlist does not.
- **ADWS from an unmanaged host** - no sensor, nothing here. The DC-side `::1` would be the only trace, and it is unattributable.
- **A collector already in the baseline** because it ran benignly during the 30-day window first - the aged-in case, rare and expensive for the attacker.
- **Encrypted or non-standard-port** directory access - 9389 is the whole surface.

## References
- `ldap-directory-reach.md` - the 389/636/3268/3269 sibling; same novelty-via-nightly-baseline design, split from this because ADWS has a different client set and the `::1` attribution hole
- MITRE T1087 (account discovery), T1069 (permission groups discovery), T1595-adjacent directory enumeration; SOAPHound / SoaPy as the ADWS-native collectors
- Schwartz, *From Code to Coverage* (TROOPERS26) - the ADWS `[::1]` attribution problem
- `docs/ESQL-CONVENTIONS.md` - FDR `event.action` lowercase, raw fields under `data.*`, and LOOKUP JOIN against a nightly-maintained baseline
