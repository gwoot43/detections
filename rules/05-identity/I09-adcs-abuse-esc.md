---
id: I09
name: AD Certificate Services abuse (ESC1/ESC6 style certificate issuance)
category: identity
status: todo
severity: high
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1649]
data_source: AD CS audit events 4886/4887 on the certificate authority
suppression:
  fields: [req_user, san]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Certificate-based attacks (Certipy, Certify) request a certificate with an attacker-chosen subject alternative name (SAN), then authenticate as that SAN. The CA logs each request (4886) and each issued certificate (4887) with the requester and the request attributes. A SAN in those attributes that names someone other than the requester is the attack, or an enrollment agent you can list.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded* METADATA _id, _index, _version
| WHERE event.code IN ("4886", "4887")             // request received / certificate issued
| EVAL requester = TO_LOWER(TO_STRING(winlog.event_data.Requester)),
       attrs = TO_LOWER(TO_STRING(winlog.event_data.Attributes)),
       request_id = TO_STRING(winlog.event_data.RequestId)
// Attributes holds one request attribute per line, e.g. "certificatetemplate:user" and "san:upn=administrator@corp.example"
| GROK attrs "san:%{NOTSPACE:san}"
| GROK attrs "certificatetemplate:%{NOTSPACE:template}"
// requester is logged as DOMAIN\user (DOMAIN\host$ for a computer), so compare the SAN with the bare name.
// LIKE needs a literal pattern in ES|QL, so use LOCATE (0 = not found) for the dynamic comparison.
| EVAL req_user = REPLACE(MV_LAST(SPLIT(requester, "\\")), "\\$$", "")
| WHERE san IS NOT NULL AND LOCATE(san, req_user) == 0
  AND NOT (requester IN ("contoso\\svc-enrollment-agent"))      // your enrollment agents
| KEEP @timestamp, winlog.computer_name, event.code, request_id, requester, req_user, san, template, _id, _version, _index
```
This needs CA audit logging enabled (auditing on the CA plus `certutil -setreg CA\AuditFilter 127`). The event has no SAN or template field of its own; both come from `Attributes`. `Requester` and `Attributes` are not in the integration's predefined field list, so the query fails with "Unknown column" until the first 4886/4887 has been indexed.

Coverage limit: a SAN placed only inside the certificate request (CSR), not repeated as a request attribute, does not appear in these events. Catch that path on the configuration side (AD06, a template that lets the enrollee supply the subject) or on the authentication side (4768 certificate logons).

## Suppression
Suppress by `req_user`, `san` for 1h. Alerts missing a key field are not suppressed. Events 4886 and 4887 fire for the same request.

## Known false positives / exclusions
- Enrollment agents legitimately requesting on behalf of others (the "enroll on behalf of" scenario). Exclude the enrollment-agent accounts and the templates they use.

## Triage
- Revoke the issued certificate, disable or fix the vulnerable template (remove ENROLLEE_SUPPLIES_SUBJECT / require manager approval), and treat the SAN identity as compromised.

## Test
In a lab AD CS, submit a certificate request for one test user that carries a `SAN:upn=` request attribute naming a second test user, and confirm 4886 records it.
