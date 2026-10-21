---
id: N09
name: Zscaler anonymizer, proxy-avoidance, unsanctioned VPN or DNS-over-HTTPS use
category: network
status: todo
language: esql
index: logs-zscaler_zia.web-*
mitre: [T1090.003, T1572, T1573]
data_source: Zscaler Internet Access web logs (Elastic zscaler_zia integration, web data stream)
suppression:
  fields: [user.name, destination.domain, outcome]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Traffic to anonymizers, Tor gateways, unsanctioned VPNs and DNS-over-HTTPS providers is how users and malware escape inspection. Legitimate use is rare on a managed fleet.

- **Anchor:** Zscaler's anonymizer, proxy-avoidance, VPN and DNS-over-HTTPS categories, Tor `.onion` names and the main DoH resolvers.
- **Output:** one row per user and destination, with how many requests and how many got through. `outcome` says which: `allowed` means the evasion worked; `blocked` means policy held (kept for context and repeat counts).
- **Rarity, for DNS-over-HTTPS only:** browsers that use DoH by default reach the same resolvers from across the fleet, so a resolver more than three users reach is that default, not evasion. One device using DoH when nobody else does is the case to look at. Anonymizers and VPNs alert whoever uses them: policy evasion by many users is still evasion.

Tunnel services (Cloudflare Tunnel, ngrok, dev tunnels) are fixed-detections 01 After A, so they aren't repeated here.

## Query
Run every 15 minutes with a 1-hour lookback.
```esql
FROM logs-zscaler_zia.web-*
| EVAL cat = TO_LOWER(TO_STRING(zscaler_zia.web.url.category.sub)), dom = TO_LOWER(TO_STRING(destination.domain)),
       doh = cat == "dns over https services"
             OR dom IN ("dns.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "dns.quad9.net", "doh.opendns.com")
// Anchor: anonymizer, proxy-avoidance, VPN and DoH traffic, and Tor .onion names. Category names: confirm in Discover.
| WHERE cat IN ("anonymizer", "proxy avoidance") OR cat LIKE "*vpn*" OR dom LIKE "*.onion*" OR doh
| EVAL got_through = CASE(event.action == "allowed", 1, 0)
// One row per user and destination: how often, and whether any request got through.
| STATS requests = COUNT(*), allowed = SUM(got_through), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        categories = VALUES(cat), source_ips = VALUES(source.ip), user_agents = VALUES(user_agent.original),
        is_doh = MAX(CASE(doh, 1, 0))
    BY user.name, destination.domain
// Rarity for DoH only: a resolver most users' browsers reach is the browser default, not evasion.
| INLINE STATS domain_users = COUNT_DISTINCT(user.name) BY destination.domain
| WHERE is_doh == 0 OR domain_users <= 3
// Allowed means the evasion worked; blocked means policy held.
| EVAL outcome = CASE(allowed > 0, "allowed", "blocked")
| KEEP user.name, destination.domain, outcome, requests, allowed, domain_users, first_seen, last_seen,
       categories, source_ips, user_agents
```
Field notes: `cat` is the Zscaler URL category (`zscaler_zia.web.url.category.sub`). Categories are matched exactly instead of by substring because a substring such as `*tor*` also matches "Cloud Storage". The exact category names above are best guesses: confirm them in Discover. Tor traffic is expected to fall under Zscaler's anonymizer category or the `.onion` domain match. `event.action` is `allowed`, `blocked` or `cautioned`.

## Suppression
Suppress by `user.name`, `destination.domain`, `outcome` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: anonymisers and VPNs stay connected, so each run's repeats fold into the open alert. `outcome` is in the key so a blocked attempt that later gets through raises a new alert.

## Known false positives / exclusions
- DoH used by a browser on only a few machines (a team that switched it on) passes the rarity check. Confirm with the users; if it's sanctioned, exclude those devices.

## Triage
- Allowed Tor or VPN traffic from a corporate host pairs with W10 (`tor.exe`, `psiphon.exe` or a VPN client on the endpoint). Investigate the host, not just the traffic. A high `requests` count of blocked attempts is software retrying, not a person. A non-browser user agent on DoH is a program resolving names outside your DNS, which malware does to hide its C2 lookups.

## Test
Browse to a known anonymizer test domain from a managed device.
