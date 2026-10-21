---
id: AD14
name: Certificate authority issued a request it had denied, or the SubCA template was requested (ESC7, officer rights abused)
category: ad-attack
status: todo
rank: 14
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1649]
data_source: AD CS audit events 4886, 4887 and 4888 on the certificate authority
suppression:
  fields: [winlog.computer_name, winlog.event_data.RequestId, finding]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
**One question:** is someone using CA officer rights to issue themselves a certificate they weren't allowed? This is ESC7. An account with the CA's "Manage Certificates" right (or "Manage CA", which can grant it) can issue any request, including one the CA refused. Certipy does it in three steps:
1. Request the `SubCA` template, which only CA administrators may enrol in, with an administrator's name in it. The CA denies it (4888), but the attacker keeps the private key.
2. Issue that denied request with the officer right (`certipy ca -issue-request <id>`). The CA logs it as issued (4887), under the same request ID.
3. Retrieve the certificate and log on as the administrator.

- **Anchor:** the CA's own audit events for one request: received (4886), issued (4887), denied (4888).
- **Corroborating property:** the same request ID denied and later issued. A certificate manager almost never turns a refusal into an issued certificate; normal approval goes through *pending* (4889), not *denied*. Or a `SubCA` request at all: subordinate CAs are built a few times in a CA's life, by its administrators.
- **Exclusion:** the CA administrators' own `SubCA` requests, as account pairs (placeholders).

AD06 catches the officer right being granted (4882); this catches it being used. I09 and AD15 catch the certificate's use.

## Query
Run hourly with a 7-day lookback, so a denied request issued days later still pairs.
```esql
FROM logs-system.security*, logs-windows.forwarded*
// 1 GATE: certificate requests received, issued and denied on the CA, with the request ID (the grouping key).
| WHERE event.code IN ("4886", "4887", "4888") AND winlog.event_data.RequestId IS NOT NULL AND winlog.computer_name IS NOT NULL
// 3 REDUCE: one row per request on each CA: when it was denied, when it was issued, and whether it asked for SubCA.
// The template is only in the request attributes; CA events are few, so reading them here is cheap.
| STATS denied_at = MIN(@timestamp) WHERE event.code == "4888",
        issued_at = MAX(@timestamp) WHERE event.code == "4887",
        subca_requests = COUNT(*) WHERE event.code == "4886"
          AND TO_LOWER(TO_STRING(winlog.event_data.Attributes)) LIKE "*certificatetemplate:subca*",
        requester = VALUES(TO_STRING(winlog.event_data.Requester)), subject = VALUES(TO_STRING(winlog.event_data.Subject)),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY winlog.computer_name, winlog.event_data.RequestId
// 4 DECIDE: a denied request later issued, or a SubCA request. No count threshold to baseline: either one happening is
// the finding. Only requests with activity in the last 2 hours alert; older ones were judged on earlier runs.
| EVAL finding = CASE(denied_at IS NOT NULL AND issued_at IS NOT NULL AND issued_at >= denied_at, "denied_request_issued",
                      subca_requests > 0, "subca_requested",
                      NULL)
| WHERE finding IS NOT NULL AND last_seen >= NOW() - 2 hours
// 5 ENRICH: one requester per request. A CA administrator building a real subordinate CA requests SubCA by design
// (placeholders: the CA host's short name as logged, and the administrator's account).
| EVAL requester = MV_MIN(requester)
| WHERE NOT (finding == "subca_requested" AND requester IN ("<domain>\\<ca_admin_account>"))
// 6 OUTPUT
| KEEP winlog.computer_name, winlog.event_data.RequestId, finding, requester, subject, denied_at, issued_at, first_seen
```
No LogScale version: the CA's logs are in Elastic.

## Rule settings
| | |
|---|---|
| Interval / lookback | hourly / 7 days. The lookback is longer than the schedule on purpose: the denial and the issuance can be days apart. Only requests with new activity in the last 2 hours alert. |
| Suppression | `winlog.computer_name`, `winlog.event_data.RequestId`, `finding` for 24h |

## Telemetry assumptions
- The CA's Security log: Certification Services auditing on (success and failure), and the CA's own audit filter set: `certutil -setreg CA\AuditFilter 127`, then restart the CA service.
- 4886, 4887 and 4888 carry `RequestId`, `Requester`, `Attributes` and `Subject`. They aren't in the integration's predefined field list, so they arrive as dynamic fields under `winlog.event_data`; confirm the names in Discover.
- `winlog.computer_name` is the CA. With event forwarding, `host.name` is the collector, so it isn't used.

Confirm the CA's events arrive, over the last day:
```esql
FROM logs-system.security*, logs-windows.forwarded*
| WHERE event.code IN ("4886", "4887", "4888", "4889")
| STATS events = COUNT(*), with_request_id = COUNT(winlog.event_data.RequestId), with_attributes = COUNT(winlog.event_data.Attributes)
    BY event.code, winlog.computer_name
```

## Before enabling: what's normal
There's no threshold to baseline, but check both findings' history over 30 days: run the query without the `last_seen` filter and the exclusion. A denied request that was later issued should be rare enough to explain one by one. Every `SubCA` request should match a subordinate CA you know about; those requesters become the exclusion.

## Suppression
Suppress by CA, request ID and finding for 24h. Alerts missing a key field are not suppressed. A request seen on several runs while it's in the 2-hour window alerts once; a `SubCA` request that is later issued alerts again as `denied_request_issued`.

## Known false positives / exclusions
- A certificate manager who denied a request by mistake and then issued it. Rare; confirm with them.
- CA administrators requesting `SubCA` for a real subordinate CA. Exclude the administrator's account for that finding only.

## Blind spots
- **Approving a pending request.** An officer can also approve their own request for a template that requires manager approval: 4889 (pending), then 4887. That's the normal approval flow, so it isn't flagged here; AD15 sees the certificate being used.
- **A template enabled for the purpose.** With "Manage CA", an attacker can publish a vulnerable template on the CA instead (`certipy ca -enable-template`). AD06 sees CA configuration changes; I09 and AD15 see the certificate.
- CA auditing off, or a CA whose Security log isn't collected.

## Triage
- Find who issued it: list the accounts with "Manage Certificates" or "Manage CA" on that CA, and look for a recent 4882 (CA permissions changed, AD06) granting it. The requester and the officer are often the same account.
- Revoke the certificate (`certutil -revoke <serial>`), then publish the CRL. A password reset doesn't stop it: the certificate stays valid until it's revoked.
- Look for its use: AD15 (a first certificate logon) for the identity in `subject`, from the requester's machine.

## Test
In a lab CA, give a test user "Manage Certificates" (and "Manage CA" if needed).
- `certipy req -ca <ca> -template SubCA -upn administrator@<lab domain>` as that user: the CA denies it; `subca_requested`.
- `certipy ca -ca <ca> -issue-request <request id>`: `denied_request_issued` within the hour.
