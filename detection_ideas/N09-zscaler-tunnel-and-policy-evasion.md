---
id: N09
name: Zscaler anonymizer, proxy-avoidance, unsanctioned VPN or DNS-over-HTTPS use
category: network
status: todo
severity: medium
language: esql
index: logs-zscaler_zia.web-*
mitre: [T1090.003, T1572, T1573]
data_source: Zscaler Internet Access web logs (Elastic zscaler_zia integration, web data stream)
suppression:
  fields: [user.name, destination.domain, severity]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Traffic to anonymizers, Tor gateways, unsanctioned VPNs and DNS-over-HTTPS providers is how users and malware escape inspection. Legitimate use is rare on a managed fleet.

Tunnel services (Cloudflare Tunnel, ngrok, dev tunnels) are fixed-detections 01 After A, so they aren't repeated here. Severity is gated on the outcome: an **allowed** connection means the evasion worked (medium); a **blocked** one means policy held (low, for context and repeat counts).

## Query
```esql
FROM logs-zscaler_zia.web-* METADATA _id, _index, _version
| EVAL cat = TO_LOWER(TO_STRING(zscaler_zia.web.url.category.sub)),
       dom = TO_LOWER(TO_STRING(destination.domain))
| WHERE cat IN ("anonymizer", "proxy avoidance", "dns over https services")   // verify value in Discover
     OR cat LIKE "*vpn*"                                                       // verify value in Discover
     OR dom LIKE "*.onion*"
     OR dom IN ("dns.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "dns.quad9.net", "doh.opendns.com")
| EVAL severity = CASE(event.action == "blocked", "low", "medium")
| KEEP @timestamp, user.name, source.ip, destination.domain, url.full, cat, event.action, severity, _id, _version, _index
```
Field notes: `cat` is the Zscaler URL category (`zscaler_zia.web.url.category.sub`). Categories are matched exactly instead of by substring because a substring such as `*tor*` also matches "Cloud Storage". The exact category names above are best guesses: confirm them in Discover. Tor traffic is expected to fall under Zscaler's anonymizer category or the `.onion` domain match. `event.action` is `allowed`, `blocked` or `cautioned`.

## Suppression
Suppress by `user.name`, `destination.domain`, `severity` for 24h. Alerts missing a key field are not suppressed. Anonymisers and VPNs stay connected. `severity` is in the key so a blocked attempt that later gets through raises a new alert.

## Known false positives / exclusions
- `dns.google` and Cloudflare DoH are used by some browsers and apps by default. If you block DoH at policy, keep this; if not, scope to endpoints where DoH should be off.

## Triage
- Allowed Tor or VPN traffic from a corporate host pairs with W10 (`tor.exe`, `psiphon.exe` or a VPN client on the endpoint). Investigate the host, not just the traffic. A climbing count of blocked attempts from one host is software retrying, not a person.

## Test
Browse to a known anonymizer test domain from a managed device.
