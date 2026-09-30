---
id: WE13
name: Domain controller machine account authenticating with NTLM to a non-DC or from an unexpected IP
category: windows-events
status: todo
severity: high
language: esql
index: logs-windows.security-*
mitre: [T1187, T1557.001]
data_source: Windows Security event 4624 on member servers
suppression:
  fields: [acct, dest]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Domain controllers normally authenticate to member servers with Kerberos. An NTLM network logon by a DC machine account on a member server, or one arriving from an IP that is not a DC, is the footprint of forced authentication and relay. It is often aimed at certificate enrollment servers, so pair it with I09.

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code == "4624"
| EVAL acct = TO_LOWER(winlog.event_data.TargetUserName),
       ap = TO_LOWER(TO_STRING(winlog.event_data.AuthenticationPackageName)),
       lt = TO_STRING(winlog.event_data.LogonType),
       dest = TO_LOWER(host.name)
| WHERE lt == "3" AND ap == "ntlm"
  AND acct IN ("dc01$", "dc02$")                                           // your DC machine accounts, or a lookup
  AND (NOT (dest LIKE "dc*") OR NOT CIDR_MATCH(source.ip, "10.0.0.10/32", "10.0.0.11/32"))   // DC IPs
| KEEP @timestamp, dest, acct, source.ip, ap, winlog.event_data.WorkstationName
```

## Suppression
Suppress by `acct`, `dest` for 1h. Alerts missing a key field are not suppressed. Forced authentication is usually retried several times.

## Known false positives / exclusions
- Occasional NTLM from a DC when a service is reached by IP instead of name. Baseline for two weeks and fix those configurations rather than excluding them.

## Triage
- Identify the source IP and isolate it if it is not a DC. Check the destination for certificate requests (I09) and new logons by the DC account.
- Hardening that removes the path: EPA and HTTPS on certificate web enrollment, SMB signing, and disabling NTLM where possible.

## Test
Validate on historical data: the rule should be silent for normal DC traffic.
