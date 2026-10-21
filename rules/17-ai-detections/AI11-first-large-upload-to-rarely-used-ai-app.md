---
id: AI11
name: First large upload by a user to an AI app few people in the organisation use (data sent to shadow AI)
category: ai
status: todo
language: esql
index: logs-zscaler_zia.web-*
mitre: [T1567]
data_source: Zscaler ZIA web logs
suppression:
  fields: [user.name, zscaler_zia.web.app.name]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Pasting a prompt into an AI app sends a few kilobytes. Uploading documents or spreadsheets to one sends megabytes. Your sanctioned AI tools (Microsoft 365 Copilot, an enterprise ChatGPT or Claude workspace) are used by many people. An AI app only one or two people use, receiving their documents for the first time, is company data leaving for a service nobody has assessed. That happens through a careless user, an insider or a compromised account.

- **Anchor:** requests to apps Zscaler classifies as AI applications that sent data.
- **Corroborating property:** the user is new to this app (their first request in the 7-day lookback was in the last 2 hours), and they sent 5 MB or more since: documents, not chat.
- **Exclusion by rarity:** the app is used by at most 3 people in the organisation. Sanctioned tools drop out with no list to keep.

## Query
Run hourly with a 7-day lookback.
```esql
FROM logs-zscaler_zia.web-*
// Anchor: requests to AI apps (Zscaler's cloud app class) that sent data.
| WHERE zscaler_zia.web.app.class LIKE "*AI*" AND http.request.bytes > 0 AND user.name IS NOT NULL
| EVAL user.name = TO_LOWER(user.name)
// One row per user and app: when they started using it in the 7 days, and how much they sent.
| STATS first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), bytes_sent = SUM(http.request.bytes), requests = COUNT(*),
        upload_files = VALUES(zscaler_zia.web.upload.file.name), dlp_rules = VALUES(zscaler_zia.web.dlp.rule.name),
        url.domain = VALUES(url.domain), source.ip = VALUES(source.ip)
    BY user.name, zscaler_zia.web.app.name
// Rarity: how many people use this app, counted before the other checks. Sanctioned tools are used by many.
| INLINE STATS app_users = COUNT_DISTINCT(user.name) BY zscaler_zia.web.app.name
// New for this user in the last 2 hours, 5 MB or more sent, to an app at most 3 people use.
| WHERE first_seen >= NOW() - 2 hours AND bytes_sent >= 5000000 AND app_users <= 3
```

**Check before deploying:** run `FROM logs-zscaler_zia.web-* | WHERE zscaler_zia.web.app.class LIKE "*AI*" | STATS users = COUNT_DISTINCT(user.name) BY zscaler_zia.web.app.class, zscaler_zia.web.app.name` over a week. That confirms the class name Zscaler uses for AI apps in your logs (`AI & ML Applications` or similar) and shows which apps are in use. Replace the `LIKE` with the exact class name once you know it.

## Suppression
Suppress by `user.name`, `zscaler_zia.web.app.name` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: the 7-day lookback overlaps every run, and a user alerts once per app, when they start.

## Known false positives / exclusions
- Someone trialling an AI tool with non-sensitive files. `upload_files` and `dlp_rules` show what was sent; close it if it's harmless and the tool is approved.

## Blind spot
- An unsanctioned AI app that many people already use isn't rare, so it never alerts. Block it or mark it in Zscaler's cloud app control instead.
- Traffic Zscaler doesn't decrypt shows no request size for its content; if an AI app is on your SSL inspection bypass list, it's invisible here.

## Triage
- What was sent: `upload_files`, any DLP rule hits, and the user's role. Customer data, source code or financials going to an unassessed AI service is a data-loss incident.
- Ask the user. Most cases are careless rather than malicious, but repeat cases or someone leaving the company are insider-risk cases (IN-series).
- Check the app: its terms (does it train on uploads?) and where it's hosted. Then decide whether to block it in Zscaler.

## Test
From a lab account, upload a 6 MB test document to an AI app nobody in your organisation uses. It should alert within the hour.
