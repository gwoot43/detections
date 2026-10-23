---
id: SWEEP-01
name: One client asking the DCs for tickets to many service accounts (Kerberoasting) or many computers (SharpHound collection)
language: esql
index: logs-yourorg-microsoft-windows*
mitre: [T1558.003, T1087.002, T1018]
data_source: Windows Security 4769 on the domain controllers
suppression:
  fields: [source.ip, user.name, finding]
  duration: 6h
  missing_fields: do_not_suppress
---
Two sweeps show up in the DCs' service-ticket events (4769), from one client and one account in an hour:
- **Service accounts.** Kerberoasting (Rubeus, `GetUserSPNs`, BloodHound's own Kerberoast step) asks for a ticket to every account with an SPN, so it can crack them offline. Normal clients touch a handful.
- **Computers.** SharpHound's session and local-admin collection connects to every computer it can reach, and on a domain-joined host each connection is a ticket to that computer's account (`HOST$`).

Only the DCs' 4769s are read. The question of which managed host and process sent the requests is answered afterwards, by the pivot query, for the one address that alerted.

Run hourly over the last hour.
```esql
FROM logs-yourorg-microsoft-windows*
// Filter for service tickets the DCs granted
| WHERE event.code == "4769" AND winevt.event_data.status == "0x0" AND source.ip IS NOT NULL
// The service each ticket is for; ticket renewals (krbtgt) and the DC's own loopback don't count
| EVAL svc = TO_LOWER(winevt.event_data.service_name)
| WHERE svc != "krbtgt" AND NOT CIDR_MATCH(source.ip, "127.0.0.0/8", "::1/128")
// Group by client address and account: how many service accounts and how many computers it asked for
| STATS service_accounts = COUNT_DISTINCT(svc) WHERE NOT ENDS_WITH(svc, "$"),
        rc4_service_accounts = COUNT_DISTINCT(svc) WHERE NOT ENDS_WITH(svc, "$")
          AND winevt.event_data.ticket_encryption_type == "0x17",
        computers = COUNT_DISTINCT(svc) WHERE ENDS_WITH(svc, "$"),
        sample = TOP(svc, 20, "asc") WHERE NOT ENDS_WITH(svc, "$"),
        dcs = VALUES(host.name), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY source.ip, user.name
// Service accounts - source: your baseline over two 10-day periods (no other client reached 30 an hour, typical
// max 12; a pentest reached 111). Computers: a starting value until baselined (query below).
| EVAL finding = CASE(service_accounts >= 25, "service_account_sweep", computers >= 100, "computer_sweep", NULL)
| WHERE finding IS NOT NULL
```
No LogScale version: the DCs' logs are in Elastic. Suppress by address, account and finding for 6h.

## Which host and process sent it
Falcon, for the alert's address only, so it's cheap. No rows means the address isn't a managed host: the attacker's own machine, or a device behind a proxy.
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Connections to AD ports from the alert's address, around first_seen
| WHERE event.action == "networkconnectip4" AND source.ip == "<source.ip>"
  AND destination.port IN (88, 389, 445, 636, 3268, 3269, 9389)
| STATS connections = COUNT(*), ports = VALUES(destination.port), first_seen = MIN(@timestamp)
    BY host.name, data.ContextBaseFileName, data.ContextProcessId
```
```logscale
#event_simpleName=NetworkConnectIP4 LocalAddressIP4="<source.ip>" RemotePort=/^(88|389|445|636|3268|3269|9389)$/
| default(field=ContextBaseFileName, value="unknown")
| groupBy([aid, ContextBaseFileName, ContextProcessId], function=[count(as=connections), collect([RemotePort])], limit=max)
| match(file="aid_master_main.csv", field=aid, include=[ComputerName], strict=false)
```
Anything other than `lsass.exe` or `svchost.exe` talking to the DCs is the tool or the proxy carrying it.

## Before turning it on
- Re-run the baseline. The earlier version counted computer accounts as service accounts (`NOT svc LIKE "$"` has no `*`, so it only excluded a service literally named `$`), so the old numbers were inflated; 25 stays safe, and may be able to come down. Set the computer threshold from the same run:
  ```esql
  FROM logs-yourorg-microsoft-windows*
  | WHERE event.code == "4769" AND winevt.event_data.status == "0x0" AND source.ip IS NOT NULL
  | EVAL svc = TO_LOWER(winevt.event_data.service_name), hour = DATE_TRUNC(1 hour, @timestamp)
  | WHERE svc != "krbtgt"
  | STATS service_accounts = COUNT_DISTINCT(svc) WHERE NOT ENDS_WITH(svc, "$"),
          computers = COUNT_DISTINCT(svc) WHERE ENDS_WITH(svc, "$")
      BY source.ip, user.name, hour
  // second STATS, baseline only: the spread across every client-hour
  | STATS p99_accounts = PERCENTILE(service_accounts, 99), max_accounts = MAX(service_accounts),
          p99_computers = PERCENTILE(computers, 99), max_computers = MAX(computers)
  ```
- Expect the computer sweep from SCCM, backup, vulnerability scanning and monitoring servers. Exclude them as address + account pairs.
- If 4769 addresses arrive as `::ffff:10.x.x.x`, strip the prefix before using them in the pivot query.

## What it misses
- SharpHound or `bloodhound.py` run from the attacker's machine over NTLM: no 4769 at all. 05 sees the proxy; an NTLM rule on the DC sees the logons.
- SharpHound's LDAP-only collection (`-c DCOnly`): no tickets to computers.
- Sweeps paced under the thresholds, and targeted Kerberoasting of a few accounts (a honey SPN catches that).

## When it fires
`service_account_sweep`: assume the tickets are being cracked offline. Check `rc4_service_accounts` (RC4 tickets crack fastest), rotate the passwords of the accounts in `sample` with weak passwords first, and run the pivot query for the process. `computer_sweep`: look for SharpHound on that host (a .NET binary or PowerShell run by a user, writing a zip of JSON files).
