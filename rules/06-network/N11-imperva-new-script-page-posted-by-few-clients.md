---
id: N11
name: New script page answering POSTs from one or two clients at the Imperva edge (webshell in use)
category: network
status: todo
severity: high
language: esql
index: logs-imperva_cloud_waf.event-*
mitre: [T1505.003, T1190]
data_source: Imperva Cloud WAF events (passed requests)
suppression:
  fields: [url.domain, url.path]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A webshell is a script page that didn't exist until the attacker uploaded it, and only the attacker uses it. Real pages are deployed to everyone and are used by many clients. In ARMORY CASTLE's BeyondTrust intrusion (Google Threat Intelligence, October 2026) the actor POSTed to a staging page, `/app_84304470%2Ephp`, then dropped the SAWFLY webshell (`mangoapi.php`) and drove it with POSTs. SAWFLY answers 404 to any request without its secret parameter, so scanners and crawlers see nothing, while the attacker gets 200.

- **Anchor:** POST requests to a server-side script page (`.php`, `.jsp`, `.aspx` and similar) that the site answered with success. An encoded dot (`%2E`) counts, since the staging upload above used one to get past path filters.
- **Corroborating property:** the page answered its first POST in the 7-day lookback in the last 2 hours, and it has had 5 or more since.
- **Exclusion by rarity:** at most two clients have POSTed to it. A new page from a release is used by many clients; a webshell is used by its operator.

L03 sees the commands a webshell runs on a Falcon host. This rule sees the webshell being used at the edge, including on servers and appliances without Falcon.

## Query
Run hourly with a 7-day lookback.
```esql
FROM logs-imperva_cloud_waf.event-*
// Anchor: POSTs the site answered with success. Filtering here cuts the volume before any counting.
| WHERE http.request.method == "POST" AND http.response.status_code >= 200 AND http.response.status_code < 300
| EVAL url.path = TO_LOWER(url.path)
// Server-side script pages only. An encoded dot (%2e) counts: it's how the staging upload slipped past path filters.
| WHERE url.path RLIKE """.*(\.|%2e)(php[0-9]?|phtml|phar|jspx?|aspx?|ashx|asmx|cfm)"""
// One row per site and page: when it first answered a POST in the 7 days, and from how many clients.
| STATS first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), requests = COUNT(*), clients = COUNT_DISTINCT(source.ip),
        source.ip = VALUES(source.ip), source.geo.country_iso_code = VALUES(source.geo.country_iso_code),
        user_agent.original = VALUES(user_agent.original)
    BY url.domain, url.path
// A page that started answering POSTs in the last 2 hours (two hourly runs), used 5+ times since, by at most 2 clients.
| WHERE first_seen >= NOW() - 2 hours AND requests >= 5 AND clients <= 2
```

**Check before deploying:** this needs Imperva's logs of requests it let through, not only its security events. Run `FROM logs-imperva_cloud_waf.event-* | STATS COUNT(*) BY event.action` over a day. Most rows should be `req-passed`. If they aren't, turn on access logs in Imperva's SIEM log settings.

## Suppression
Suppress by `url.domain`, `url.path` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: the 7-day lookback overlaps every run, and continued use of the page folds into the open alert.

## Known false positives / exclusions
- A page released this hour and first exercised by one tester. Check it against the deployment; it stops alerting once it has a history.
- An admin page that hasn't been POSTed to for a week, used again by one admin. Same check: is the page in the application's source?

## Triage
- Is the page in the application's code or deployment? A page nobody shipped is a webshell. Pull it from the server and hash it.
- `source.ip` is the operator. Search all Imperva and Zscaler logs for it, and look for other new pages it reached.
- On a Falcon host, look for `php-fpm`, `httpd` or `java` starting shells at the same times (L03), and for what the shells ran (L07, L13, L14, L15).

## Test
Deploy a lab page (`lab-test.php`) behind Imperva that returns 200 to POSTs, and POST to it 5 times from one address. It should alert within the hour.
