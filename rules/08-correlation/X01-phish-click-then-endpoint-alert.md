---
id: X01
name: Email phishing interaction followed by endpoint alert on the same user's host
category: correlation
status: todo
severity: critical
language: esql
index: logs-mimecast.ttp_url_logs-*, logs-crowdstrike.alert-*
mitre: [T1566, T1204, T1059]
data_source: Mimecast URL Protect click logs (E01) + CrowdStrike Falcon alerts (CS04) joined on the user
suppression:
  fields: [usr]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A malicious click on its own is a warning; an endpoint alert on its own has context missing. Together, a phishing click and a Falcon detection for the same user shortly after is a confirmed successful attack chain, and it is one of the highest-value detections you can run. This is the reason to ingest email and endpoint into the same platform.

## Prerequisite
- The join key is the user name. Mimecast gives the recipient's email address and Falcon gives the account name (`crowdstrike.alert.user_principal` when set, otherwise `user.name`). The query compares the part before the `@`, lowercased, with any `DOMAIN\` prefix removed. If your email local part differs from your sAMAccountName (for example `john.smith@` against `jsmith`), this rule cannot pair them. Check a few users in Discover first.
- If you also use Defender for Office Safe Links, add `logs-o365.audit-*` and a third branch on `event.action == "TIUrlClickData"` (see E05). That field set only exists after the first Safe Links click record arrives, so the query fails with "Unknown column" until then.

## Query
```esql
FROM logs-mimecast.ttp_url_logs-*, logs-crowdstrike.alert-*
| WHERE @timestamp > NOW() - 2 hours
| EVAL verdict = TO_LOWER(mimecast.scanResult),
       mc_action = TO_LOWER(mimecast.action),
       override = TO_LOWER(COALESCE(mimecast.userOverride, "none")),
       awareness = TO_LOWER(COALESCE(event.action, "")),
       product = TO_LOWER(crowdstrike.alert.product)
// click: a real user click (not the delivery-time scan) that was malicious, or that the user forced past a block or warning page
// endpoint: a Falcon endpoint detection of medium severity or above, or any OverWatch finding
| EVAL click = event.dataset == "mimecast.ttp_url_logs" AND mimecast.creationMethod == "User Click"
         AND (verdict == "malicious" OR (mc_action IN ("block", "warn") AND (override != "none" OR awareness == "continue"))),
       alert = event.dataset == "crowdstrike.alert"
         AND (product == "overwatch" OR (product == "epp" AND crowdstrike.alert.severity >= 40))
| WHERE click OR alert
| EVAL raw_user = CASE(click, MV_FIRST(user.email), COALESCE(crowdstrike.alert.user_principal, user.name)),
       usr = TO_LOWER(MV_FIRST(SPLIT(MV_LAST(SPLIT(raw_user, "\\")), "@"))),
       click_ts = CASE(click, @timestamp, NULL),
       alert_ts = CASE(alert, @timestamp, NULL),
       click_url = CASE(click, url.original, NULL),
       sender = CASE(click, MV_FIRST(email.from.address), NULL),
       alert_name = CASE(alert, crowdstrike.alert.name, NULL),
       alert_host = CASE(alert, TO_LOWER(COALESCE(host.name, host.hostname)), NULL),
       alert_cmd = CASE(alert, process.command_line, NULL)
| WHERE usr IS NOT NULL AND usr != ""
| STATS first_click = MIN(click_ts), last_alert = MAX(alert_ts), clicks = COUNT(click_ts), alerts = COUNT(alert_ts),
        click_urls = VALUES(click_url), senders = VALUES(sender), alert_names = VALUES(alert_name),
        hosts = VALUES(alert_host), alert_command_lines = VALUES(alert_cmd)
    BY usr
// both sides present, and at least one alert came after a click
| WHERE first_click IS NOT NULL AND last_alert IS NOT NULL AND last_alert >= first_click
| EVAL minutes_click_to_alert = DATE_DIFF("minute", first_click, last_alert)
| KEEP usr, first_click, last_alert, minutes_click_to_alert, hosts, alert_names, alert_command_lines, click_urls, senders, clicks, alerts
```
Run every 15 minutes. The 2-hour lookback is the correlation window: a click and a later alert for the same user anywhere in it pair up. There is no `BUCKET`, so a pair is never split across a bucket edge.

Field notes:
- Mimecast URL logs also contain delivery-time scans (`creationMethod` "Entry Scan"). Only "User Click" rows are clicks.
- The integration moves `userAwarenessAction` into `event.action` and the recipient into `user.email`. The values for a forced click-through (`mimecast.userOverride`, and `event.action` "Continue" on a `warn` page) are unverified: check them in Discover.
- Falcon severity is 0-100 (medium starts at 40). The sample PUP detections score 30, so they don't pair. EPP alerts often carry the host in `host.hostname` only.

## Suppression
Suppress by `usr` for 24h. Alerts missing a key field are not suppressed. Correlation rule: the pair stays in the lookback for two hours, so every run in that time re-matches it.

## Known false positives / exclusions
- Very low. A malicious click plus an unrelated medium Falcon detection for the same user within two hours is possible. Check that `hosts` is the user's own machine and that the alert follows the click.
- Shared or generic mailboxes whose local part matches a service account name. Exclude those `usr` values.

## Triage
- This is a live intrusion. Isolate the host, reset the user, pull the payload from the click URL, and expand to full IR.

## Test
In a lab, click a Mimecast test URL that is classed malicious as a lab user, then trigger a benign medium-severity Falcon test detection on that user's host within the hour.
