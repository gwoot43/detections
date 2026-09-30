---
id: I09
name: AD Certificate Services abuse (ESC1/ESC6 style certificate issuance)
category: identity
status: todo
severity: high
language: esql
index: logs-windows.security-*
mitre: [T1649]
data_source: Windows Security events 4886/4887 (CA) and 4768 (certificate logon) from CA and DCs
suppression:
  fields: [req_user, san]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Certificate-based attacks (Certipy, Certify) request a certificate on a vulnerable template with an attacker-chosen subject alternative name, then authenticate as that SAN. The signals are a certificate request where the requester and the SAN identity differ, and Kerberos logons via certificate (PKINIT) that do not match normal smartcard users.

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code IN ("4886", "4887", "4888")     // cert request received / approved / denied
| EVAL requester = TO_LOWER(COALESCE(winlog.event_data.Requester, winlog.event_data.SubjectUserName)),
       subject = TO_LOWER(TO_STRING(winlog.event_data.Subject)),
       san = TO_LOWER(TO_STRING(winlog.event_data.SubjectAlternativeName)),
       template = TO_LOWER(TO_STRING(winlog.event_data.CertificateTemplate))
// requester is logged as DOMAIN\user and the SAN as upn=user@domain, so compare on the bare username.
// LIKE needs a literal pattern in ES|QL, so use LOCATE (0 = not found) for the dynamic comparison.
| EVAL req_user = MV_LAST(SPLIT(requester, "\\"))
| WHERE san != "" AND san IS NOT NULL
  AND LOCATE(san, req_user) == 0
| KEEP @timestamp, host.name, requester, req_user, subject, san, template
```
This needs CA audit logging enabled (auditing on the CA plus `certutil -setreg CA\AuditFilter 127`). Pair with a PKINIT logon rule on 4768 with a certificate info field for the authentication side.

## Suppression
Suppress by `req_user`, `san` for 1h. Alerts missing a key field are not suppressed. Events 4886 and 4887 fire for the same request.

## Known false positives / exclusions
- Enrollment agents legitimately requesting on behalf of others (the "enroll on behalf of" scenario). Exclude the enrollment-agent accounts and the templates they use.

## Triage
- Revoke the issued certificate, disable or fix the vulnerable template (remove ENROLLEE_SUPPLIES_SUBJECT / require manager approval), and treat the SAN identity as compromised.

## Test
In a lab AD CS, request a certificate on a template with supply-in-request enabled specifying a different SAN.
