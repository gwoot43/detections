---
id: CERTIPY-01
name: NTLM logon where the client claims to be the server it's logging on to (Certipy's own NTLM)
language: esql
index: logs-yourorg-microsoft-windows*
mitre: [T1649, T1087.002]
data_source: Windows Security 4624 and 4625 on the domain controllers and certificate authorities
suppression:
  fields: [host.name, source.ip]
  duration: 1h
  missing_fields: do_not_suppress
---
Certipy builds its own NTLM messages, and fills in the client's workstation name with the server's own name, taken from the server's challenge. So when it binds to LDAP on a DC (`find`, `account`, `shadow`, `template`) or authenticates to web enrolment on the CA (`req -web`), that server logs a network logon from a "workstation" with its own name, coming from another address. Windows clients send their own name; nothing legitimate claims to be the server it's talking to.

It doesn't care what the attacker's machine is called or whether it's behind a SOCKS proxy.

Run every 15 minutes over the last 20.
```esql
FROM logs-yourorg-microsoft-windows*
// Filter for NTLM network logons, successful or failed, on the DCs and CAs (placeholders)
| WHERE event.code IN ("4624", "4625") AND winevt.logon.type == "3"
  AND winevt.event_data.authentication_package_name == "NTLM"
  AND host.name IN ("<dc_1>", "<dc_2>", "<ca_1>")
// Short names of the server and of the workstation the client claims to be
| EVAL server = TO_LOWER(MV_FIRST(SPLIT(host.name, "."))),
       claimed = TO_LOWER(MV_FIRST(SPLIT(winevt.event_data.workstation_name, ".")))
// Keep clients that claim to be the server itself, from another address
| WHERE claimed == server AND NOT CIDR_MATCH(source.ip, "127.0.0.0/8", "::1/128")
// Display results
| KEEP @timestamp, host.name, event.code, winevt.event_data.workstation_name, user.name, source.ip
```
Suppress by server and source address for an hour.

## Before turning it on
- Run `certipy find` in a lab and check the 4624 on the DC shows the DC's own name as the workstation. This comes from reading Certipy 5's source; older versions used a different NTLM library and may send the attacker's hostname or nothing, which a rule on unknown workstation names catches instead.
- Run it over 30 days. If a server logs connections to itself with its own address instead of loopback, add `source.ip != host.ip` (or that server's address).
- Check the field names (`winevt.logon.type`, `winevt.event_data.workstation_name`, `source.ip`) against a 4624 in Discover.
- Drop the host filter to watch every server.

## What it misses
- `certipy req` over its default transport (SMB to the CA): that goes through Impacket's NTLM, which sends a different name. 03 sees it.
- Kerberos (`-k`): no NTLM logon at all. 04 and 05 see the connections; AD16 the logon.

## When it fires
`source.ip` is the attacker's machine, or the host proxying for it. Check that host in Falcon for the proxy process (05), and the CA for requests from `user.name` (AD14, I09).
