---
id: B04
name: Lateral sweep over SMB, RPC, RDP, WinRM or LDAP from one host (catches by behaviour: SharpHound/BloodHound collection, PsExec/Impacket sweeps, CrackMapExec/NetExec)
category: behaviour
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1021, T1570, T1018, T1087.002, T1069.002, T1049]
data_source: CrowdStrike FDR network connection events
suppression:
  fields: [host.id, process.name, severity]
  duration: 2h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
When an operator moves laterally at scale with CrackMapExec, NetExec, Impacket or a PsExec loop, one host reaches many others on the remote-execution ports (SMB, RPC, WinRM, RDP) in a short time. BloodHound/SharpHound, ADExplorer and similar collectors have a related shape: they query the directory over LDAP and then reach out to a large share of domain computers for sessions and local admins. This counts distinct internal destinations per process, independent of the tool, so a renamed binary is caught the same way. A workstation does not WinRM or RDP to dozens of machines in ten minutes, and it does not query several domain controllers from one process.

Three labelled tiers, in the `label` and `severity` columns:
- `ldap_and_lateral_sweep` (high): the sweep threshold is met and the same process also queried a domain controller over LDAP. This is the directory-collection shape: SharpHound queries LDAP, then connects to port 445 on every computer it found before enumerating sessions and local admins.
- `lateral_sweep` (high): 15 or more distinct targets on SMB/RPC, WinRM or RDP.
- `ldap_dc_fanout` (medium): one process connecting over LDAP, LDAPS or the Global Catalog to 3 or more distinct directory servers. LDAP fan-out is a different shape from SMB fan-out (an estate has a handful of domain controllers, not hundreds), so it has its own, lower threshold.

## Query
Run every 10 minutes with a 15-minute lookback.
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action == "NetworkConnectIP4"
  AND host.os.type == "windows" AND destination.ip IS NOT NULL
  AND destination.port IN (5985, 5986, 3389, 135, 445, 389, 636, 3268, 3269)
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| EVAL process.name = TO_LOWER(COALESCE(process.name, "unknown")),
       protocol = CASE(destination.port IN (5985, 5986), "winrm",
                       destination.port == 3389, "rdp",
                       destination.port IN (389, 636, 3268, 3269), "ldap",
                       "smb_rpc")
// exclude admin jump hosts, patch and management servers here, e.g. AND host.name NOT IN ("jump01", "sccm01")
// Netlogon (inside lsass.exe) pings several DCs over LDAP to locate one; that is normal DC discovery, not enumeration
| WHERE NOT (protocol == "ldap" AND process.name == "lsass.exe")
| STATS targets = COUNT_DISTINCT(CASE(protocol != "ldap", destination.ip, NULL)),
        winrm = COUNT_DISTINCT(CASE(protocol == "winrm", destination.ip, NULL)),
        rdp = COUNT_DISTINCT(CASE(protocol == "rdp", destination.ip, NULL)),
        ldap_targets = COUNT_DISTINCT(CASE(protocol == "ldap", destination.ip, NULL)),
        protocols = VALUES(protocol),
        conns = COUNT(*),
        host.name = VALUES(host.name)
    BY host.id, process.name, BUCKET(@timestamp, 10 minutes)
| WHERE targets >= 15 OR ldap_targets >= 3
| EVAL label = CASE(targets >= 15 AND ldap_targets >= 1, "ldap_and_lateral_sweep",
                    targets >= 15, "lateral_sweep",
                    "ldap_dc_fanout"),
       severity = CASE(targets >= 15, "high", "medium")
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=NetworkConnectIP4 event_platform=Win
| in(field="RemotePort", values=["5985", "5986", "3389", "135", "445", "389", "636", "3268", "3269"])
| cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
| pname := lower(ContextBaseFileName)
| default(field=pname, value="unknown", replaceEmpty=true)
| case {
    in(field="RemotePort", values=["5985", "5986"])
      | protocol := "winrm" | target_ip := RemoteAddressIP4 | winrm_ip := RemoteAddressIP4;
    RemotePort=3389
      | protocol := "rdp" | target_ip := RemoteAddressIP4 | rdp_ip := RemoteAddressIP4;
    in(field="RemotePort", values=["389", "636", "3268", "3269"])
      | protocol := "ldap" | ldap_ip := RemoteAddressIP4;
    *
      | protocol := "smb_rpc" | target_ip := RemoteAddressIP4;
  }
// exclude admin jump hosts, patch and management servers here, e.g. | !in(field="ComputerName", ignoreCase=true, values=["jump01", "sccm01"])
// Netlogon (inside lsass.exe) pings several DCs over LDAP to locate one; that is normal DC discovery, not enumeration
| (protocol!="ldap" OR pname!="lsass.exe")
| bucket_start := @timestamp - (@timestamp % 600000)
| groupBy([aid, pname, bucket_start], function=[count(target_ip, distinct=true, as=targets), count(winrm_ip, distinct=true, as=winrm),
                                               count(rdp_ip, distinct=true, as=rdp), count(ldap_ip, distinct=true, as=ldap_targets),
                                               collect([protocol, ComputerName]), count(as=conns)], limit=max)
| test(targets >= 15 OR ldap_targets >= 3)
| case {
    test(targets >= 15 AND ldap_targets >= 1) | label := "ldap_and_lateral_sweep" | severity := "high";
    test(targets >= 15) | label := "lateral_sweep" | severity := "high";
    * | label := "ldap_dc_fanout" | severity := "medium";
  }
| bucket_start := formatTime(format="%F %T", field=bucket_start, timezone="Australia/Sydney")
```
`targets` counts SMB/RPC, WinRM and RDP destinations only; `ldap_targets` counts directory servers on 389, 636, 3268 and 3269. Keep the source scoped to workstations if your servers legitimately fan out; exclude server names inline. Lower `ldap_targets` to 2 in an estate with only two domain controllers per site, or raise it if one process normally talks to several. FDR connection events name the process only on sensors that send `ContextBaseFileName`; otherwise `process.name` reads `unknown`, the row covers every process on the host, and the `lsass.exe` exclusion cannot apply, so expect DC-locator noise in the LDAP tier on those sensors.

## Suppression
Suppress by `host.id`, `process.name`, `severity` for 2h. Alerts missing a key field are not suppressed. Aggregating rule. A sweep spans buckets; a new source still alerts. `severity` is in the key so an LDAP-only fan-out that turns into a lateral sweep raises a new alert. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on, so it is an output column, not a key.

## Known false positives / exclusions
- Admin jump hosts and management servers that administer many machines. Exclude them inline by host name.
- Patch and configuration tools using WinRM or WMI broadly, and inventory scanners. Exclude their process and host.
- Legitimate AD tooling run by admins (PingCastle on a schedule) and servers that query several domain controllers or Global Catalogs by design (Exchange, Entra Connect, ADFS, identity-governance and monitoring servers). Exclude the host and process inline.

## Triage
- Find the process and account. `protocols` and the tier say which shape it is.
- `lateral_sweep`: map to the destinations and check those for new services or shells (W08). A lateral sweep plus credential access on the source (B08, W01) is hands-on-keyboard movement.
- `ldap_and_lateral_sweep` or `ldap_dc_fanout`: a user workstation enumerating the directory is reconnaissance for lateral movement. Look at the LDAP and RPC connections in Discover, check the host for collector tooling (W09), and isolate it if the process is not a known admin tool.

## Test
Run a CrackMapExec or NetExec sweep across a lab subnet from a lab host. For the LDAP tiers, run a BloodHound/SharpHound collection against a lab domain with at least three domain controllers from a lab workstation.
