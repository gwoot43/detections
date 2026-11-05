---
id: AD19
name: ADWS directory access — an unusual client on 9389 (SOAPHound-class)
category: ad-attack
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1069, T1087]
data_source: CrowdStrike FDR / Windows Security events
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
AD Web Services (**TCP 9389**) answers the same directory queries as LDAP, over SOAP. SOAPHound and SoaPy use it **specifically to avoid LDAP rules**: the collection that would light up 389/636 instead rides 9389, where most estates are not looking. The legitimate client set is small and stable - the AD PowerShell module (`powershell.exe`, `pwsh.exe`, `powershell_ise.exe`), WinRM remoting (`wsmprovhost.exe`), the AD Administrative Center (`dsac.exe`) - so a **non-native client on ADWS at all** is the signal, and a native client at **abnormal volume** is the second shape.

Below: a **deployable** ES|QL variant (2-hour lookback), a **bucketed** ES|QL variant (one row per 2-hour window, for replaying against live data), and a **LogScale/CQL** version of the bucket. The 389/636/3268/3269 sibling is `ldap-directory-reach.md`.

### Deployable (ES|QL, 2-hour lookback)
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Deploy with the rule's lookback set to 2 hours: the window is the schedule, there is no bucket.
| WHERE @timestamp >= NOW() - 2 hours
  AND event.action IN ("networkconnectip4", "networkconnectip6")
  AND data.ConnectionDirection == "0"
  AND data.event_platform == "Win"
  AND destination.port == 9389
// CIDR is a function on a field, so compute it once after the gate. fc00::/7 is unique-local; add your
// global IPv6 prefix if the DCs hold one.
| EVAL internal_dest = CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
| WHERE internal_dest
// Base file name, falling back to the kernel-attributed name, so a renamed or kernel-issued client is kept.
| EVAL proc = TO_LOWER(COALESCE(process.name, data.ContextBaseFileName, "unknown")),
       native = proc IN ("powershell.exe", "powershell_ise.exe", "pwsh.exe", "wsmprovhost.exe", "dsac.exe", "svchost.exe")
| WHERE proc != "unknown"
| STATS directory_servers = COUNT_DISTINCT(destination.ip),
        connections = COUNT(*),
        servers_seen = MV_SLICE(VALUES(destination.ip), 0, 19),
        host.name = VALUES(host.name),
        event.start = MIN(@timestamp), event.end = MAX(@timestamp)
    BY host.id, process.name = proc, native
// A non-native client on ADWS at all is the SOAPHound-class signal; a native client at abnormal volume is
// the second shape, kept because a compromised admin box can drive the sanctioned PowerShell AD module.
// source: 30-day replay - native clients sit at a handful of DCs; nothing benign reaches 6+ servers or 50+
// connections over ADWS in the window.
| WHERE native == false OR connections >= 50 OR directory_servers >= 6
| EVAL finding = CASE(native == false, "adws_unusual_client", "adws_heavy_use")
| SORT directory_servers DESC
| LIMIT 100
```
Deploy every 2 hours over the last 2 hours. Suppress by `host.id` + `process.name` + `finding` for 24h.

### Bucketed (ES|QL, 2-hour windows — for live testing)
Same logic, a `DATE_TRUNC` bucket instead of a lookback, so you can run it across a long range and read each 2-hour window on its own.
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action IN ("networkconnectip4", "networkconnectip6")
  AND data.ConnectionDirection == "0"
  AND data.event_platform == "Win"
  AND destination.port == 9389
| EVAL internal_dest = CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"),
       time_bucket = DATE_TRUNC(2 hours, @timestamp)
| WHERE internal_dest
| EVAL proc = TO_LOWER(COALESCE(process.name, data.ContextBaseFileName, "unknown")),
       native = proc IN ("powershell.exe", "powershell_ise.exe", "pwsh.exe", "wsmprovhost.exe", "dsac.exe", "svchost.exe")
| WHERE proc != "unknown"
| STATS directory_servers = COUNT_DISTINCT(destination.ip),
        connections = COUNT(*),
        servers_seen = MV_SLICE(VALUES(destination.ip), 0, 19),
        host.name = VALUES(host.name),
        event.start = MIN(@timestamp), event.end = MAX(@timestamp)
    BY time_bucket, host.id, process.name = proc, native
// source: as above - 30-day replay; native clients sit at a handful of DCs.
| WHERE native == false OR connections >= 50 OR directory_servers >= 6
| EVAL finding = CASE(native == false, "adws_unusual_client", "adws_heavy_use")
| SORT time_bucket DESC
| LIMIT 100
```

### LogScale (CQL, bucketed)
NetworkConnect events carry no image name, so attach it from ProcessRollup2 by `aid` + process id (`defineTable` + `match`). 2-hour buckets. Confirm the field names (`RemotePort`, `ConnectionDirection`, `RemoteAddressIP4`, `ContextProcessId`, `TargetProcessId`, `event_platform`) against your LogScale repo before trusting it.
```logscale
#event_simpleName=/^NetworkConnect(IP4|IP6)$/
| ConnectionDirection="0"
| event_platform="Win"
| RemotePort="9389"
| cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
// attach the image name from ProcessRollup2 by aid + process id
| defineTable(name="procs", include=[aid, TargetProcessId, ImageFileName],
    query={#event_simpleName=/ProcessRollup2$/})
| match(table="procs", field=[aid, ContextProcessId], column=[aid, TargetProcessId], include=[ImageFileName], strict=true)
| proc := lower(ImageFileName)
| case {
    in(proc, values=["*\\powershell.exe", "*\\powershell_ise.exe", "*\\pwsh.exe", "*\\wsmprovhost.exe", "*\\dsac.exe", "*\\svchost.exe"]) | native := "true" ;
    * | native := "false" ;
  }
| bucket(span=2h, field=@timestamp)
| groupBy([_bucket, aid, proc, native],
    function=[count(RemoteAddressIP4, distinct=true, as=directory_servers), count(as=connections),
              collect([ComputerName])], limit=max)
// Alert conditions. deliberately no * branch: a non-native client at all, or a native one at abnormal
// volume. source: 30-day replay - native clients sit at a handful of DCs over ADWS.
| case { test(native == "false") ; test(connections >= 50) ; test(directory_servers >= 6) ; }
| sort(directory_servers, order=desc, limit=100)
```

## Reading the alert
- **`finding = adws_unusual_client`** is the one to run down: a non-native process speaking ADWS. ADWS exists to answer LDAP without touching 389, so a non-PowerShell/`dsac` client on 9389 is near-certain SOAPHound-class.
- **`host.name`** is the box to isolate. ADWS records the DC-side client as `::1`, so the endpoint sensor is the only place the real source exists - which is why this rule is on FDR network telemetry, not a DC log.
- **`directory_servers`** is the fan-out; **`connections`** the depth. SoaPy/SOAPHound pulling the directory shows as many connections, often to one or two DCs.
- **`finding = adws_heavy_use`** is a native client at abnormal volume - triage, not a confirmed intrusion; usually a legitimate admin script, occasionally a driven one.

## Nearest benign twins
- **The AD PowerShell module / AD Administrative Center** run by an admin. Native, so they only reach `adws_heavy_use`, and only if one suddenly sweeps many DCs.
- **A monitoring or identity-governance product** that reads AD over ADWS under its own binary. If it is non-native it will fire once - confirm and add it to the exception set as an entity pair (`proc` + host).
- **`svchost.exe`** hosting a legitimate ADWS-using service: kept native for that reason, at the cost of masking a svchost-injected collector - tune if your estate does not expect ADWS from svchost.

## What it misses
- **A collector that renames itself to a native binary** (drops `powershell.exe` into a path and runs it) - the native allowlist passes it. The `ldap-directory-reach.md` approach (fan-out breadth regardless of name) is the backstop on 389/636.
- **ADWS from an unmanaged host** - no sensor, and the DC-side `::1` is unattributable.
- **Encrypted or non-standard-port** directory access - 9389 is the whole surface.

## References
- `ldap-directory-reach.md` - the 389/636/3268/3269 sibling; split from this because ADWS has a different client set and the `::1` attribution hole
- MITRE T1087 (account discovery), T1069 (permission groups discovery); SOAPHound / SoaPy as the ADWS-native collectors
- Schwartz, *From Code to Coverage* (TROOPERS26) - the ADWS `[::1]` attribution problem
- `docs/ESQL-CONVENTIONS.md` and `docs/DETECTION-STRUCTURE-CQL.md` - FDR field conventions and the LogScale `defineTable`/`match` idiom
