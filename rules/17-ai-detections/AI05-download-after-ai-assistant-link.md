---
id: AI05
name: Program downloaded from an unknown site that an AI assistant sent the user to (AI result poisoning)
category: ai
status: todo
severity: high
language: esql
index: logs-zscaler_zia.web-*
mitre: [T1608.007, T1204.002]
data_source: Zscaler ZIA web logs
suppression:
  fields: [user.name, site]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
People now ask an AI assistant where to download a tool, and attackers plant pages so the assistant recommends theirs. ATT&CK v20 calls this AI Result Poisoning (T1608.007). The assistant links to a lookalike site, and the user downloads an installer that's malware. Real vendors' sites are known to Zscaler and categorised. Poisoned ones are new.

- **Anchor:** two kinds of allowed request, both rare: a visit that came from an AI assistant, and a program download (Zscaler file class `Executables`). A visit counts as coming from an assistant when the assistant's page is the referrer, or the URL carries the `utm_source` tag ChatGPT and others add to the links they give.
- **Corroborating property:** the same user downloaded a program from the site the assistant sent them to, either from the site itself or from a page on it.
- **Exclusion:** the site is one Zscaler has no reputation for (`Miscellaneous or Unknown`, `Newly Registered Domains`). Downloads from known vendors drop out.

## Query
Run every 15 minutes with a 1-hour lookback.
```esql
FROM logs-zscaler_zia.web-*
| WHERE event.action == "allowed" AND url.domain IS NOT NULL
| EVAL ref = TO_LOWER(COALESCE(http.request.referrer, "")), url.domain = TO_LOWER(url.domain), user.name = TO_LOWER(user.name),
       // Came from an AI assistant: its page as the referrer, or the utm_source tag assistants add to the links they give.
       from_ai = ref RLIKE "https?://([a-z0-9-]+\\.)*(chatgpt\\.com|openai\\.com|perplexity\\.ai|copilot\\.microsoft\\.com|gemini\\.google\\.com|claude\\.ai|deepseek\\.com|grok\\.com)(/.*)?"
                 OR TO_LOWER(COALESCE(url.query, "")) RLIKE ".*utm_source=(chatgpt\\.com|perplexity|copilot|gemini|claude).*",
       is_download = zscaler_zia.web.file.class == "Executables"
// Anchor: only those two kinds of request go on, so the counting below is cheap.
| WHERE from_ai OR is_download
// The site the user landed on: a visit's own domain; for a download, the page it was started from (or its own domain).
| EVAL site = CASE(from_ai OR ref == "", url.domain, REPLACE(ref, "^https?://([^/:]+).*$", "$1"))
// One row per user and site: did they arrive from an assistant, and did they download a program from it.
| STATS ai_visits = SUM(CASE(from_ai, 1, 0)), downloads = SUM(CASE(is_download, 1, 0)),
        unknown_site = MAX(CASE(from_ai AND zscaler_zia.web.url.category.sub IN ("Miscellaneous or Unknown", "Newly Registered Domains"), 1, 0)),
        first_seen = MIN(@timestamp), http.request.referrer = VALUES(CASE(from_ai, ref, NULL)),
        url.original = VALUES(CASE(is_download, url.original, NULL)), file.name = VALUES(zscaler_zia.web.file.name),
        source.ip = VALUES(source.ip)
    BY user.name, site
// Sent there by an assistant, downloaded a program, and Zscaler doesn't know the site.
| WHERE ai_visits > 0 AND downloads > 0 AND unknown_site == 1
```

**Check before deploying:**
- Run `FROM logs-zscaler_zia.web-* | STATS COUNT(*) BY zscaler_zia.web.file.class` over a day to confirm the value Zscaler uses for programs in your logs; it's assumed to be `Executables`.
- Check that `http.request.referrer` and `url.query` are populated for ordinary browsing. If your NSS feed doesn't send the referrer, the `utm_source` tag is still in the URL.

## Suppression
Suppress by `user.name`, `site` for 24h. Alerts missing a key field are not suppressed.

## Known false positives / exclusions
- A small legitimate project's download page, new to Zscaler, that an assistant recommended. Check the file's signer and hash before closing; small open-source projects are also what poisoned answers imitate.

## Blind spot
- A download that starts from a second site (a file host the landing page links to) isn't tied back to the visit. The landing page still shows as the referrer if the link is followed in the same tab.
- Assistants that strip the referrer and add no tag to their links aren't recognised.

## Triage
- Compare `site` with the real vendor's domain. Lookalike spelling, a different top-level domain, or a page copied from the vendor is the pattern.
- Find the file on the user's device (CrowdStrike: a new executable from the browser's download folder) and whether it ran. If it did, treat the device as compromised: these installers are usually infostealers.
- Ask the user what they asked the assistant; the same answer may have reached colleagues.

## Test
From a lab device, open a link to a test download on a newly registered lab domain with `?utm_source=chatgpt.com` appended, then download an `.exe` from that page. The rule should alert within 15 minutes.
