---
id: N12
name: PHP2Shell exploitation at the edge (CVE-2026-109618, CVE-2026-109619) - the upload-progress field the exploit uses, POSTs crashing PHP workers, or Imperva's own verdict
category: network
status: todo
language: esql
index: logs-imperva_cloud_waf.event-*
mitre: [T1190]
data_source: Imperva Cloud WAF event logs, with request bodies
suppression:
  fields: [url.domain, source.ip, finding]
  duration: 24h
  missing_fields: do_not_suppress
---
PHP2Shell (CVE-2026-109618 and CVE-2026-109619, patched on 21 October 2026 in PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35) lets an unauthenticated attacker run code through PHP itself. A small multipart POST abuses PHP's session upload-progress handling to corrupt memory while PHP is still parsing the request, so it works against any page PHP serves and the application never logs anything. What the WAF can still see:

- **The field the exploit needs.** The body carries `PHP_SESSION_UPLOAD_PROGRESS`. Real upload progress bars use it too, so on its own it only counts when few clients are sending it to that site.
- **Crashed workers.** Failed attempts, and the warm-up requests a working exploit needs, kill PHP workers. The origin answers 5xx: PHP-FPM gives a 502, mod_php loses its Apache child. The field plus a crash is close to certain. A burst of crashes for one client, while the rest of the site is fine, is the next best thing; an outage gives errors to everyone.
- **Imperva's own verdict,** once Imperva ships a rule for it.

Run every 15 minutes over the last 20.

```esql
FROM logs-imperva_cloud_waf.event-*
// Only three kinds of request get read: POSTs whose body has the upload-progress field (full-text MATCH, answered by
// the index), POSTs the origin answered with a server error, and anything Imperva flagged.
| WHERE ((http.request.method == "POST" AND MATCH(message, "PHP_SESSION_UPLOAD_PROGRESS"))
         OR (http.request.method == "POST" AND http.response.status_code >= 500 AND http.response.status_code <= 599)
         OR imperva_cloud_waf.event.name IS NOT NULL)
  AND source.ip IS NOT NULL AND url.domain IS NOT NULL
// Per site and client. The LIKE and RLIKE only ever run on the handful of rows above.
| STATS upload_field_posts = COUNT(*) WHERE http.request.method == "POST" AND message LIKE "*PHP_SESSION_UPLOAD_PROGRESS*",
        upload_field_crashes = COUNT(*) WHERE http.request.method == "POST" AND http.response.status_code >= 500
          AND message LIKE "*PHP_SESSION_UPLOAD_PROGRESS*",
        crashed_posts = COUNT(*) WHERE http.request.method == "POST" AND http.response.status_code >= 500,
        php2shell_verdicts = COUNT(*) WHERE TO_LOWER(TO_STRING(imperva_cloud_waf.event.name)) RLIKE ".*(php2shell|cve-2026-10961[89]).*",
        passed_verdicts = COUNT(*) WHERE TO_LOWER(TO_STRING(imperva_cloud_waf.event.name)) RLIKE ".*(php2shell|cve-2026-10961[89]).*"
          AND TO_LOWER(TO_STRING(event.action)) == "req-passed",
        paths = COUNT_DISTINCT(url.path), sample_paths = TOP(url.path, 5, "asc"),
        status_codes = VALUES(http.response.status_code), user_agents = TOP(user_agent.original, 3, "asc"),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY url.domain, source.ip
// How many clients each site gave errors to, and how many sent the field: an outage or a real progress bar involves
// many; an attack, the few sending it.
| INLINE STATS clients_with_errors = COUNT(*) WHERE crashed_posts > 0,
               clients_with_field = COUNT(*) WHERE upload_field_posts > 0
    BY url.domain
// Most specific first. The 3s are starting values until you've checked a week of your own traffic (baseline below).
| EVAL finding = CASE(passed_verdicts > 0, "imperva_verdict_passed",
                      php2shell_verdicts > 0, "imperva_verdict_blocked",
                      upload_field_crashes > 0, "upload_progress_post_crashed",
                      crashed_posts >= 3 AND clients_with_errors <= 3, "worker_crash_burst",
                      upload_field_posts > 0 AND clients_with_field <= 3, "upload_progress_post",
                      NULL)
| WHERE finding IS NOT NULL
// Sites with real upload progress bars (field-only alerts), and your own scanners (crash alerts). Placeholders.
| WHERE NOT (finding == "upload_progress_post" AND url.domain IN ("<site_with_upload_progress_bar>"))
  AND NOT (finding == "worker_crash_burst" AND CIDR_MATCH(source.ip, "198.51.100.0/24"))
| KEEP url.domain, source.ip, finding, upload_field_posts, upload_field_crashes, crashed_posts, php2shell_verdicts,
       passed_verdicts, clients_with_errors, clients_with_field, paths, sample_paths, status_codes, user_agents,
       first_seen, last_seen
```
Suppress by site, client and finding for 24h, so a field-only POST that later crashes the worker still raises a new alert.

## Before turning it on
- **Where the body lives.** This assumes the POST body is in `message`. If your pipeline puts it in its own field (say `http.request.body.content`), use that in the `MATCH` and the `LIKE`s. Open a POST in Discover and check you can see its multipart parts (`Content-Disposition: form-data; name="..."`). Also check whether bodies are logged for every POST or only for flagged ones, and how much of each body is kept.
- **`MATCH` needs a recent Elastic** (8.18 or 9.x). If it complains about `MATCH` inside an `OR`, split the field check into its own copy of the rule.
- **Imperva's rule name** is a guess (`php2shell` or the CVE numbers). Once Imperva announces its rule, look at what it logs in `imperva_cloud_waf.event.name` and fix the pattern.
- **Find your progress-bar sites.** These are the ones that legitimately get the field. They go in the exclusion:
  ```esql
  FROM logs-imperva_cloud_waf.event-*
  | WHERE http.request.method == "POST" AND MATCH(message, "PHP_SESSION_UPLOAD_PROGRESS")
  | STATS posts = COUNT(*), clients = COUNT_DISTINCT(source.ip) BY url.domain
  | SORT clients DESC
  ```
- **Check the crash threshold** against a normal week, so a buggy form that 500s on retry doesn't page you:
  ```esql
  FROM logs-imperva_cloud_waf.event-*
  | WHERE http.request.method == "POST" AND http.response.status_code >= 500 AND http.response.status_code <= 599
    AND source.ip IS NOT NULL AND url.domain IS NOT NULL
  | EVAL win = DATE_TRUNC(15 minutes, @timestamp)
  | STATS crashed_posts = COUNT(*) BY url.domain, source.ip, win
  // second STATS, baseline only: the per-site spread of errored POSTs per client in a window
  | STATS p99 = PERCENTILE(crashed_posts, 99), max = MAX(crashed_posts) BY url.domain
  | SORT p99 DESC
  ```

## What it can miss
- A first-try success with no crash, no Imperva rule and no logged body. That looks like any other POST; the endpoint side has to catch what happens next.
- A site that renamed the field (`session.upload_progress.name`), or a field name split or encoded to dodge matching.
- Sites not behind Imperva.
- Mod_php crashes that Imperva logs as a dropped connection rather than a 5xx. Worth checking how your origin's crashes show up.

## When it fires
Check whether the site runs PHP and which version. Patched sites are still being attacked, so block the source anyway. For a crash or a passed verdict, look at the origin around `first_seen`:
- the PHP-FPM log for a child dying on a signal, or Apache's error log for a segmentation fault;
- then anything new from the web server or PHP workers: processes, connections, `.php` files.

Finally, check whether the same client hit your other sites.
