---
id: CERTIPY-03
name: Certificate requested over the cert named pipe on the CA (certipy req's default transport)
language: esql
index: logs-yourorg-microsoft-windows*
mitre: [T1649]
data_source: Windows Security 5145 on the certificate authorities
suppression:
  fields: [host.name, source.ip]
  duration: 1h
  missing_fields: do_not_suppress
---
`certipy req` asks for the certificate over SMB, through the `cert` named pipe on the CA (MS-ICPR). Windows' own enrolment (autoenrolment, certreq, the certificates console) uses DCOM instead, so on a CA the pipe should be close to silent.

Run every 15 minutes over the last 20.
```esql
FROM logs-yourorg-microsoft-windows* METADATA _id, _index, _version
// Filter for access to the cert pipe on the certificate authorities (placeholders)
| WHERE event.code == "5145" AND host.name IN ("<ca_1>", "<ca_2>")
  AND winevt.event_data.relative_target_name == "cert"
// Display results
| KEEP @timestamp, host.name, user.name, source.ip, winevt.event_data.share_name, winevt.event_data.relative_target_name,
       _id, _index, _version
```
Suppress by CA and source address for an hour.

## Before turning it on
- 5145 needs "Audit Detailed File Share" on the CA. It's noisy on file servers but light on a CA.
- Run `certipy req` in a lab and check the 5145 shows `relative_target_name` as `cert`, and the field names match.
- Run it over 30 days to confirm nothing legitimate uses the pipe.

## What it misses
- `certipy req -dynamic-endpoint` (RPC over TCP) and `-web` (HTTP). 01 sees the web route.
- `certipy find`'s remote registry calls use the `winreg` pipe instead. Adding `"winreg"` catches them too, but vulnerability scanners use it as well, so baseline it first.

## When it fires
Find the request on the CA (4886/4887, AD14 and I09) and what was asked for: the template and any subject alternative name. `source.ip` is the attacker's machine or its proxy (05).
