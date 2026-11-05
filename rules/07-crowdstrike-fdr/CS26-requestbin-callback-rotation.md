---
id: CS26
name: Request-bin and OAST callbacks — rotating endpoints as C2
category: crowdstrike-fdr
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1071.001, T1102, T1568.002]
data_source: CrowdStrike FDR / Windows Security events
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
In fractured-chain reporting of ARTEX in the wild (Zscaler ThreatLabz, October 2026), the operator pulled PowerShell and batch scripts with native `curl` and posted command output back to the attacker across **491 rotating `webhook.site` URLs**. Rotating endpoint names is the whole trick: each URL is used once, so per-URL reputation, blocklists and allowlists all see a brand-new hostname every time.

The rotation is the detection. No legitimate product registers dozens of throwaway endpoints on a request-bin service from one host in an hour, and the domains that exist *only* for attacker callbacks - Burp Collaborator's `oast.*`, `burpcollaborator.net`, `interact.sh`, `dnslog.cn`, `requestrepo.com` - have no business traffic at all.

```esql
FROM logs-yourorg-crowdstrike-data-default*
// One hour, stated in the query: rotation happens inside a single exfiltration or C2 session.
| WHERE @timestamp >= NOW() - 1 hour
  AND event.action == "dnsrequest"
| EVAL name = TO_LOWER(TO_STRING(dns.question.name)),
       parent = TO_LOWER(TO_STRING(dns.question.registered_domain))
| WHERE parent IS NOT NULL AND parent != ""
// Two tiers, because they fail differently. Attack-only services have no legitimate caller; the dual-use
// ones are real products a developer might use once, so they need the rotation test.
| EVAL tier = CASE(
        parent IN ("oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me", "oast.wtf",
                   "burpcollaborator.net", "interact.sh", "dnslog.cn", "requestrepo.com",
                   "canarytokens.com", "dnslog.link", "ceye.io"), "attack_only",
        parent IN ("webhook.site", "requestbin.net", "requestbin.com", "pipedream.net", "pipedream.com"), "dual_use",
        "")
| WHERE tier != ""
| STATS endpoints = COUNT_DISTINCT(name, 4000),
        lookups = COUNT(*),
        attack_only = COUNT(*) WHERE tier == "attack_only",
        samples = MV_SLICE(VALUES(name), 0, 8),
        pids = MV_SLICE(VALUES(process.entity_id), 0, 5),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.id, host.name
// Either an attack-only service was touched at all, or a dual-use service was used with rotating names.
// 3 endpoints is a starting value with no measured source yet: a developer testing a webhook uses one and
// repeats it, so the baseline at the foot of this file is what would tune it down to 2 if the estate is clean.
| WHERE attack_only >= 1 OR endpoints >= 3
| SORT endpoints DESC
| LIMIT 100
```

Deploy every 15 minutes over the last hour. Suppress by `host.id` for 24h.

## Reading the alert
- **`endpoints`** is the rotation count. In the ARTEX case it is in the hundreds within one session; three or more with `pids` pointing at the same process is already conclusive.
- **`samples`** shows the random-looking subdomains. Request-bin names are usually words or UUIDs; a sequence of them under one parent from one host is the pattern.
- **`attack_only`** needs no interpretation: a laptop resolving `abc123.oast.pro` is a tool being used, because Collaborator and its peers exist only to receive callbacks.
- **`pids`** is the attribution - resolve `process.entity_id` against `processrollup2`. `curl.exe` and `powershell.exe` are the reported pair; a browser is the benign reading.

## Nearest benign twins
- **A developer testing a webhook integration** against `webhook.site`. One endpoint, from a workstation, from a browser or a local dev server - the rotation test removes it, and `attack_only` never fires.
- **Penetration testers using Burp Collaborator** on an authorised engagement. This is the one case that will alert and should: entity-pair it by tester account and source host for the engagement window rather than suppressing the domain.
- **Deception and canary infrastructure** that your own team deployed (`canarytokens.com`). If you run canary tokens, exclude your own token hostnames by name, not the parent domain.

## What it misses
- **Rotating endpoints on domains not in this list.** Any VPS with wildcard DNS provides the same rotation; this rule covers the services that appear in reported tradecraft, and the general case is a DNS volume-and-novelty problem rather than a domain list.
- **Callback over HTTPS to an IP address**, with no DNS at all. That is a network rule, not this one.
- **A single endpoint used once** on a dual-use service. Deliberately allowed through as benign, and it is the shape a careful operator would choose.
- **Encrypted DNS**, where the name never reaches this event.

## Baseline
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 30 days
  AND event.action == "dnsrequest"
| EVAL name = TO_LOWER(TO_STRING(dns.question.name)),
       parent = TO_LOWER(TO_STRING(dns.question.registered_domain))
| WHERE parent IN ("webhook.site", "requestbin.net", "requestbin.com", "pipedream.net", "pipedream.com",
                  "oast.pro", "oast.live", "interact.sh", "dnslog.cn", "requestrepo.com")
| STATS endpoints = COUNT_DISTINCT(name, 4000), hosts = COUNT_DISTINCT(host.id) BY parent
| SORT endpoints DESC
```
Any parent with activity in the estate before you deploy is either a sanctioned integration or somebody's overdue test - both are the entity pairs this rule needs.

## References
- Zscaler ThreatLabz, ARTEX campaign analysis (October 2026) - the 491 rotating `webhook.site` URLs used to post command output, and the Kudu API staging: `zscaler.com/blogs/security-research/threat-actor-abuses-agentic-ai-pentesting-framework-target-south-korean`
- Google Threat Intelligence Group / Mandiant, *ARTEX and Friends* - framework architecture and the velocity that makes rotation necessary: `cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks`
- MITRE T1071.001 (web protocols), T1568.002 (domain generation), T1102 (web service as C2)
