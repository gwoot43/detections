---
id: X01
name: Email phishing interaction followed by endpoint alert on the same user's host
category: correlation
status: todo
severity: critical
language: esql
index: logs-*
mitre: [T1566, T1204, T1059]
data_source: Mimecast/O365 (E01/E04/E05) + CrowdStrike (W/L/CS series) joined on user and host
---
## Why this is high fidelity
A malicious click on its own is a warning; an endpoint alert on its own has context missing. Together, a phishing interaction and an endpoint detection for the same user within an hour is a confirmed successful attack chain, and it is one of the highest-value detections you can run. This is the reason to ingest email and endpoint into the same platform.

## Approach
Correlation across indices is easiest as an Elastic "indicator match" or a scheduled transform, but ES|QL can express it with LOOKUP JOIN once your identity fields line up (email address to `user.name` to `host.name`). Prerequisite: a user-to-host mapping (from FDR logons or an asset inventory) so an email click by a user can be tied to that user's endpoint.

## Query (pattern)
```esql
FROM logs-crowdstrike.fdr-* METADATA _id
| WHERE @timestamp > NOW() - 1 hour
  AND (event.action == "ProcessRollup2" OR event.action LIKE "*Detect*")
  AND host.os.type IN ("windows", "linux")
| EVAL usr = TO_LOWER(user.name)
// bring in recent phishing interactions keyed by user
| LOOKUP JOIN email_phish_clicks_last_2h ON usr
| WHERE clicked_at IS NOT NULL AND @timestamp >= clicked_at
| KEEP @timestamp, usr, host.name, process.name, process.command_line, clicked_url, clicked_at
```
Build `email_phish_clicks_last_2h` as an enrich index or transform from E01/E04/E05 (fields: `usr`, `clicked_at`, `clicked_url`). If LOOKUP JOIN is not available in your version, implement this as an Elastic indicator-match rule: indicator index = phishing clicks, event index = endpoint alerts, match on user, look-back 1 hour.

## Known false positives / exclusions
- Very low. A click plus an unrelated benign endpoint event is possible; scope the endpoint side to the suspicious rules (W02, W03, W04, CS04, CS06), not all process events, to keep it clean.

## Triage
- This is a live intrusion. Isolate the host, reset the user, pull the payload from the click URL, and expand to full IR.

## Test
In a lab, click a test malicious URL as a user, then run a benign Atomic on that user's host within the hour.
