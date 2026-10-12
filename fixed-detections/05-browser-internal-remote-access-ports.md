# 05 · Browser internal remote-access port activity (Falcon)

**Verdict before:** noisy, with a fragile exclusion.
**After:** a browser making RDP or WinRM connections to internal hosts alerts on any connection. SMB needs several distinct internal targets, because intranet pages routinely link to file shares. The exclusion moves before the aggregation, and the browser list is complete.

## Before
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.dataset == "crowdstrike.data" AND event.action == "networkconnectip4"
| WHERE destination.ip IS NOT NULL AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
| WHERE destination.port IN (445, 3389, 5985, 5986)
| WHERE data.ContextBaseFileName IN ("chrome.exe", "msedge.exe", "firefox.exe")
| EVAL time_bucket = DATE_TRUNC(30 minutes, @timestamp), process_name = TO_LOWER(data.ContextBaseFileName),
    port_family = CASE( destination.port == 445, "smb", destination.port == 3389, "rdp", "remote-management" )
| STATS events = COUNT(*), distinct_targets = COUNT_DISTINCT(destination.ip), destination.port = VALUES(destination.port),
    destination.ip = VALUES(destination.ip), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
  BY time_bucket, host.name, process_name, port_family
| WHERE events >= 1
| WHERE NOT (port_family == "remote-management" AND distinct_targets == 1 AND MV_FIRST(destination.ip) == "192.0.2.10")
| SORT first_seen ASC
```

## What's wrong

| # | Problem | Effect |
|---|---|---|
| 1 | SMB at one connection. A browser opening a `\\server\share` link from an intranet or SharePoint page connects to 445. | The main source of noise. |
| 2 | The exclusion uses `MV_FIRST(destination.ip)` on a `VALUES()` list, after aggregation. | It only works when that host is the sole target in the bucket. One more target in the same 30 minutes and it stops excluding. |
| 3 | Case-sensitive browser list missing Brave, Opera and the Edge WebView2 runtime. | Gaps, and a renamed-case binary slips through. |
| 4 | Fixed 30-minute buckets and `SORT`. | Bucket-edge splits; `SORT` does nothing in a rule. |
| 5 | Grouped by `host.name`. | If Falcon's host enrichment is missing, every host groups together. `host.id` is always present. |

## After
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action == "networkconnectip4"
  AND TO_LOWER(data.ContextBaseFileName) IN ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
                                             "iexplore.exe", "msedgewebview2.exe")
  AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
  AND destination.port IN (445, 3389, 5985, 5986)
  AND NOT (destination.port IN (5985, 5986) AND destination.ip == TO_IP("192.0.2.10"))   // approved WinRM gateway
| EVAL port_family = CASE(destination.port == 445, "smb", destination.port == 3389, "rdp", "winrm")
| STATS connections = COUNT(*), targets = COUNT_DISTINCT(destination.ip), target_ips = VALUES(destination.ip),
        browsers = VALUES(data.ContextBaseFileName), hostnames = VALUES(host.name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.id, port_family
| WHERE port_family IN ("rdp", "winrm") OR (port_family == "smb" AND targets >= 3)
```
Run every 15 minutes with a 1-hour lookback. Suppress by `host.id`, `port_family` for 12h.

- The exclusion now drops the gateway's events before counting, so other targets in the same window still alert.
- If a web-based RDP or WinRM gateway is in use, add its IP to the same exclusion line rather than raising thresholds.

## Before vs after

| | Before | After |
|---|---|---|
| SMB from one intranet share link | Alerts | Needs 3+ distinct internal targets |
| RDP / WinRM from a browser | Alerts | Alerts |
| Gateway exclusion | Breaks when a second target appears | Applied per event, always works |
| Browsers covered | 3, case-sensitive | 7, case-insensitive |
| Grouping | `host.name` + 30-minute buckets | `host.id` over the rule lookback |

## Test
From a lab host, open a browser to `http://<internal host>:3389/` and to `http://<internal host>:5985/wsman`. Each should alert. Opening one `\\fileserver\share` link should not.
