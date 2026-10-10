---
id: N09
name: Zscaler anonymizer, tunnel or SSL-inspection bypass usage
category: network
status: todo
severity: medium
language: esql
index: logs-zscaler_zia.web-*
mitre: [T1090.003, T1572, T1573]
data_source: Zscaler Internet Access web logs (Elastic zscaler_zia integration, web data stream)
suppression:
  fields: [user.name, destination.domain]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Traffic to anonymizers, Tor gateways, unsanctioned VPNs and DNS-over-HTTPS providers is how users and malware escape inspection. Combined with attempts that hit SSL-inspection-bypass categories, this catches both evasion and covert channels. Legitimate use is rare on a managed fleet.

## Query
```esql
FROM logs-zscaler_zia.web-* METADATA _id, _index, _version
| EVAL cat = TO_LOWER(TO_STRING(zscaler_zia.web.url.category.sub)),
       dom = TO_LOWER(TO_STRING(destination.domain))
| WHERE cat IN ("anonymizer", "proxy avoidance", "dns over https services")   // verify value in Discover
     OR cat LIKE "*vpn*"                                                       // verify value in Discover
     OR dom LIKE "*.onion*" OR dom LIKE "*trycloudflare*" OR dom LIKE "*.workers.dev"
     OR (dom LIKE "*ngrok*" AND NOT dom IN ("ngrok.com", "www.ngrok.com", "dashboard.ngrok.com", "download.ngrok.com"))   // vendor site, not a tunnel
     OR dom IN ("dns.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "dns.quad9.net", "doh.opendns.com")
| KEEP @timestamp, user.name, source.ip, destination.domain, url.full, cat, event.action
```
Field notes: `cat` is the Zscaler URL category (`zscaler_zia.web.url.category.sub`). Categories are matched exactly instead of by substring because a substring such as `*tor*` also matches "Cloud Storage". The exact category names above are best guesses: confirm them in Discover. Tor traffic is expected to fall under Zscaler's anonymizer category or the `.onion` domain match. `event.action` is `allowed`, `blocked` or `cautioned`.

## Suppression
Suppress by `user.name`, `destination.domain` for 24h. Alerts missing a key field are not suppressed. Tunnels and anonymisers stay connected.

## Known false positives / exclusions
- `dns.google` and Cloudflare DoH are used by some browsers and apps by default. If you block DoH at policy, keep this; if not, scope to endpoints where DoH should be off.
- Sanctioned developer use of Cloudflare Workers or ngrok. Exclude those users, but note W10 covers the endpoint side.

## Triage
- Tor or a fresh Cloudflare tunnel from a corporate host pairs with W10 (tunnel binary on the endpoint). Investigate the host, not just the traffic.

## Test
Browse to a known anonymizer test domain from a managed device.
