---
id: CLICKONCE-02
name: ClickOnce deployment downloaded through Zscaler (.application manifest or .deploy files, T1127.002)
language: esql
index: logs-zscaler_zia.web-*
mitre: [T1127.002, T1566.002, T1204.002]
data_source: Zscaler ZIA web logs
suppression:
  fields: [user.name, url.domain]
  duration: 24h
  missing_fields: do_not_suppress
---
Installing a ClickOnce app fetches a deployment manifest (`<app>.application`) and then the app's files, each served with `.deploy` added to its name (`<app>.exe.deploy`). Both extensions are rare on the web, so a request for either from a site you don't deploy ClickOnce apps from is a ClickOnce install being attempted. Zscaler sees it before anything runs, and sees blocked attempts too; 06 confirms whether the app actually started.

Run every 15 minutes over the last 20.
```esql
FROM logs-zscaler_zia.web-*
// Filter for ClickOnce deployment manifests and application files
| WHERE url.extension IN ("application", "deploy")
// Leave out the sites you deploy ClickOnce apps from (placeholders)
| WHERE NOT url.domain IN ("<clickonce_deployment_host>")
// Group by user and site
| STATS first_seen = MIN(@timestamp), requests = COUNT(*), files = TOP(url.path, 10, "asc"),
        actions = VALUES(event.action), source_ips = VALUES(source.ip)
    BY user.name, url.domain
```
Suppress by user and site for 24h.

## Before turning it on
- Check that `url.extension` is filled in (without the dot) on your Zscaler events. If it isn't, use `url.path LIKE "*.application" OR url.path LIKE "*.deploy"` instead; it's slower, because every request is read.
- Run it over 30 days. The sites that show up every day are your own ClickOnce deployments (internal tools, vendor apps); they go in the exclusion.
- Zscaler only sees the path where it inspects TLS. A ClickOnce install from an uninspected site shows only the domain; 06 still sees the app run.

## What it misses
- A deployment from one of your excluded sites, or from a site Zscaler doesn't inspect.
- Devices that don't go through Zscaler.

## When it fires
Check `actions`: blocked means it stopped here. If it was allowed, look on the device for a program started by `dfsvc.exe` around `first_seen` (06), and look up the site.
