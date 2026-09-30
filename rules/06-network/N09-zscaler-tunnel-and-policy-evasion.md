---
id: N09
name: Zscaler anonymizer, tunnel or SSL-inspection bypass usage
category: network
status: todo
severity: medium
language: esql
index: logs-zscaler.zia_web-*
mitre: [T1090.003, T1572, T1573]
data_source: Zscaler Internet Access web logs
---
## Why this is high fidelity
Traffic to anonymizers, Tor gateways, unsanctioned VPNs and DNS-over-HTTPS providers is how users and malware escape inspection. Combined with attempts that hit SSL-inspection-bypass categories, this catches both evasion and covert channels. Legitimate use is rare on a managed fleet.

## Query
```esql
FROM logs-zscaler.zia_web-*
| EVAL cat = TO_LOWER(TO_STRING(COALESCE(zscaler.zia.url_category, rule.category))),
       dom = TO_LOWER(TO_STRING(destination.domain))
| WHERE cat LIKE "*anonymizer*" OR cat LIKE "*proxy*avoid*" OR cat LIKE "*tor*" OR cat LIKE "*vpn*"
     OR dom LIKE "*.onion*" OR dom LIKE "*ngrok*" OR dom LIKE "*trycloudflare*" OR dom LIKE "*.workers.dev"
     OR dom IN ("dns.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "dns.quad9.net", "doh.opendns.com")
| KEEP @timestamp, user.name, source.ip, destination.domain, url.full, cat, event.action
```

## Known false positives / exclusions
- `dns.google` and Cloudflare DoH are used by some browsers and apps by default. If you block DoH at policy, keep this; if not, scope to endpoints where DoH should be off.
- Sanctioned developer use of Cloudflare Workers or ngrok. Exclude those users, but note W10 covers the endpoint side.

## Triage
- Tor or a fresh Cloudflare tunnel from a corporate host pairs with W10 (tunnel binary on the endpoint). Investigate the host, not just the traffic.

## Test
Browse to a known anonymizer test domain from a managed device.
