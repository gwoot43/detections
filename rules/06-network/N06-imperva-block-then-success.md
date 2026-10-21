---
id: N06
name: Imperva source heavily blocked then receives an application success
category: network
status: todo
language: esql
index: logs-imperva_cloud_waf.event-*
mitre: [T1190, T1595.002]
data_source: Imperva Cloud WAF security and access events (Elastic imperva_cloud_waf integration, event data stream)
suppression:
  fields: [source.ip, url.domain]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
An attacker probes, gets blocked many times, then finds a request the WAF allows through and the app answers with success. That block-then-2xx transition from a single source on the same endpoint is a strong sign of a bypass or a working exploit, and it filters out both the pure noise of blocked probes and the noise of normal traffic.

## Query
```esql
FROM logs-imperva_cloud_waf.event-*
| EVAL act = TO_LOWER(TO_STRING(event.action)),
       code = TO_INTEGER(http.response.status_code),
       path = TO_LOWER(url.path),
       blocked = CASE(act LIKE "req-blocked*", 1, 0),   // value unverified: Imperva REQ_BLOCKED* lowercased, "_" -> "-"
       success = CASE(act == "req-passed" AND code >= 200 AND code < 300, 1, 0)
| WHERE blocked == 1 OR success == 1
| STATS blocks = SUM(blocked), successes = SUM(success),
        first_block = MIN(CASE(blocked == 1, @timestamp, NULL)),
        last_success = MAX(CASE(success == 1, @timestamp, NULL)),
        methods = VALUES(http.request.method), attacks = VALUES(imperva_cloud_waf.event.name)
    BY source.ip, url.domain, path
// the same endpoint was blocked, then answered 2xx to this source after the first block
| WHERE blocks >= 5 AND successes >= 1 AND first_block <= last_success
```
Run every 10 minutes with a 30-minute lookback. The lookback is the window. There is no `BUCKET`, so blocks and a later success are never split across a bucket edge.

The success has to be on a path that was blocked for the same source. A scanner that trips the WAF on one page and gets a 200 from the home page no longer matches. Five blocks on one path is a deliberate attempt at that endpoint, not a stray signature hit.

Field notes: `event.action` is Imperva's `act` value, lowercased with `_` replaced by `-`. A passed request is `req-passed`. `http.response.status_code` comes from Imperva's response-code field (`cn1`). The success side only works if Imperva's SIEM log configuration sends access events (CEF name "Normal") as well as security events. If it sends only security events, no 2xx requests reach Elastic.

## Suppression
Suppress by `source.ip`, `url.domain` for 1h. Alerts missing a key field are not suppressed. Aggregating rule. Overlapping lookbacks would re-alert.

## Known false positives / exclusions
- Scanners that fuzz one endpoint and then send a clean baseline request to it. Look at `methods` and the passed request itself. If this is frequent, also require `http.request.method` POST or PUT for the success.

## Triage
- Look at the successful request in full. If it carries an attack payload and returned 2xx, treat as exploitation and pivot to the app host.

## Test
From a lab source, trip the WAF repeatedly then request a normal page on the same site.
