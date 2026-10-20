---
id: D04
name: Decoy host name looked up, or decoy host connected to (OpenCanary, decoy DNS records)
category: deception
status: todo
severity: critical
rank: 2
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1018, T1046, T1021, T1135]
data_source: CrowdStrike FDR DnsRequest and NetworkConnectIP4 from every managed host. OpenCanary JSON log (option B).
suppression:
  fields: [host.id, decoy]
  duration: 4h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A decoy host is an OpenCanary VM, or any small VM running fake SMB, RDP, SSH or HTTP, with tempting DNS names such as `pam01`, `vault-prod` or `sqlbak01` (the host behind the honey SPN in D01). Nothing legitimate is configured to use it. A managed host **resolving** one of those names means someone found it in DNS, AD, an SPN or a lure document and is checking it out. A **connection** to its IP is someone probing or trying credentials.

Falcon logs DNS lookups and outbound connections from every managed host, so this needs nothing new on the endpoints. It catches the lookup even if the attacker never connects.

## Prerequisite
- Create the DNS records (A records in AD-integrated DNS) for the decoy names, pointing at the decoy VM.
- Replace the placeholder names and IP in the deployed rule only.

## Query
**Option A: Falcon DNS and connections (recommended)**
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action IN ("dnsrequest", "networkconnectip4")
| EVAL q = TO_LOWER(COALESCE(dns.question.name, "")),
       short_name = MV_FIRST(SPLIT(q, ".")),
       dst = TO_STRING(destination.ip)
| EVAL decoy = CASE(
         event.action == "dnsrequest" AND short_name IN ("<decoy_name_1>", "<decoy_name_2>", "<decoy_name_3>"), CONCAT("dns:", short_name),
         event.action == "networkconnectip4" AND dst IN ("<decoy_ip_1>"), CONCAT("connect:", dst),
         NULL)
| WHERE decoy IS NOT NULL
// scanners and monitoring that sweep every IP (placeholders: Falcon agent IDs)
| WHERE NOT host.id IN ("<vuln_scanner_aid>", "<monitoring_aid>")
| KEEP @timestamp, host.id, host.name, user.name, decoy, q, dst, destination.port, process.name, process.command_line, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(DnsRequest|NetworkConnectIP4)$/
| case {
    #event_simpleName=DnsRequest DomainName=/^(?<short_name>[^.]*)/
      | short_name := lower(short_name)
      | in(field="short_name", values=["<decoy_name_1>", "<decoy_name_2>", "<decoy_name_3>"])
      | decoy := format("dns:%s", field=[short_name]);
    #event_simpleName=NetworkConnectIP4 in(field="RemoteAddressIP4", values=["<decoy_ip_1>"])
      | decoy := format("connect:%s", field=[RemoteAddressIP4]);
  }
// scanners and monitoring that sweep every IP (placeholders: Falcon agent IDs)
| !in(field="aid", values=["<vuln_scanner_aid>", "<monitoring_aid>"])
| select([@timestamp, aid, ComputerName, UserName, decoy, DomainName, RemoteAddressIP4, RemotePort, ContextBaseFileName, CommandLine])
```
Matching on the **first DNS label** catches both `vault-prod` and `vault-prod.corp.local`. If a decoy name could collide with a real public host name, match on the full name instead.

The exclusion and the suppression use `host.id` (the Falcon agent ID), which every FDR event carries. `host.name` is only filled when the CrowdStrike integration's "Enrich Host and User Metadata" option is on, and `NOT host.name IN (...)` drops every row where it's empty.

**Option B: OpenCanary log**

OpenCanary writes one JSON line per interaction (`logtype`, `src_host`, `dst_port`, `logdata`). Ship `/var/tmp/opencanary.log` with an Elastic Agent **Custom Logs (filestream)** integration, dataset `opencanary.log`, with JSON parsing turned on. This catches hosts Falcon doesn't cover, such as network devices, unmanaged laptops and Linux boxes without the sensor.
```esql
FROM logs-opencanary.log-*
| WHERE TO_INTEGER(logtype) >= 2000                  // 1xxx are OpenCanary's own start-up and status messages
  AND NOT src_host IN ("<vuln_scanner_ip>", "<monitoring_ip>")
| STATS hits = COUNT(*), ports = VALUES(dst_port), types = VALUES(logtype), first_seen = MIN(@timestamp)
    BY src_host
```
Turn on OpenCanary's `portscan` module (logtype 5001). It reads the decoy's own firewall log, so it sees nmap SYN scans and masscan, which send raw packets that Falcon's connection events on the scanning host may not record (the B01 blind spot). Field names depend on how the JSON is parsed. With the default parser they arrive at the top level, as shown. If you set a JSON target, prefix the fields with it.

## Suppression
Suppress by `host.id`, `decoy` for 4h. Alerts missing a key field are not suppressed. A scan of the decoy produces many connections. A different source host or decoy still alerts.

## Known false positives / exclusions
- **Vulnerability scanners, asset discovery, CMDB and monitoring** sweep every IP and so will hit the decoy. Exclude their agent IDs in the scanner WHERE (and their `src_host` in option B). This is the only routine noise. Agree it with the scanner owner so the decoy isn't flagged as a finding.
- **DNS scavenging and zone transfers** run on DNS servers, which don't produce DnsRequest events for the names they hold.
- **An admin who saw the record** and looked it up out of curiosity. Brief the DNS and server teams.

## Triage
- The source host is either compromised or being used by the red team. Look at `process.name` and `process.command_line`: `nslookup`, `ping`, `Test-NetConnection`, an RDP or SSH client, or a scanner.
- Find where the attacker learned the name: SPN enumeration (D01), a lure document (D03), or a DNS zone dump. That narrows down how far their reconnaissance got.

## Test
From a lab host with Falcon, run `nslookup <decoy_name_1>` and `Test-NetConnection <decoy_ip_1> -Port 445`. Both should alert.
