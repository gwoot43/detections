---
id: W10
name: Unapproved remote management or tunnelling tool executed
category: endpoint-windows
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1219, T1572, T1090, T1105]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, pname]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Ransomware affiliates and help-desk social engineering crews drop a second remote-management tool or a tunnel for persistence and C2. You have one approved RMM, and it runs across the fleet every day. Anything else on the list, appearing on a host for the first time, is an intrusion or shadow IT that must go.

- **Anchor:** one of the remote-management or tunnelling tools below starts, matched by file name. The list is the rule's subject, so it stays.
- **Corroborating property:** the tool is new on this host: its first run in the 7-day lookback was in the last 2 hours.
- **Exclusion by rarity:** before those 2 hours, the tool ran on at most three hosts. Your approved RMM, and anything IT uses routinely (Quick Assist, TeamViewer), has a fleet-wide history and drops out with no list to edit. A tool an intruder pushes to many hosts today still alerts on every one, because it has no history.

## Query
Run hourly with a 7-day lookback.
```esql
FROM logs-crowdstrike.fdr-*
// Anchor: a remote-management or tunnelling tool starts, matched by file name.
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL pname = TO_LOWER(process.name)
| WHERE pname IN ("anydesk.exe", "screenconnect.clientservice.exe", "screenconnect.windowsclient.exe", "connectwisecontrol.client.exe", "ateraagent.exe",
                  "splashtop_streamer.exe", "rustdesk.exe", "teamviewer.exe", "teamviewerqs.exe", "quickassist.exe",
                  "logmein.exe", "gotoassist.exe", "supremo.exe", "ammyy.exe", "ultraviewer_desktop.exe", "zohoassist.exe", "meshagent.exe", "syncro.exe", "dwagent.exe", "rport.exe", "netsupport.exe", "client32.exe", "remotepc.exe", "radmin.exe",
                  "ngrok.exe", "cloudflared.exe", "chisel.exe", "ligolo.exe", "ligolo-agent.exe", "frpc.exe", "bore.exe", "socat.exe", "gost.exe", "tailscale.exe", "zerotier-one.exe", "psiphon.exe", "tor.exe", "proxifier.exe", "devtunnel.exe")
// One row per host and tool: when it first ran in the lookback, and what ran.
| STATS first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), runs = COUNT(*),
        users = VALUES(user.name), parents = VALUES(process.parent.name), exe = VALUES(process.executable),
        cmd = VALUES(process.command_line), sha256 = VALUES(process.hash.sha256), host.name = VALUES(host.name)
    BY host.id, pname
// Rarity: how many hosts ran this tool before the last 2 hours. Approved and routine tools have a fleet-wide history;
// a tool an intruder pushes to many hosts today has none, so it still alerts everywhere.
| EVAL ran_before = CASE(first_seen < NOW() - 2 hours, host.id, NULL)
| INLINE STATS baseline_hosts = COUNT_DISTINCT(ran_before) BY pname
// New on this host in the last 2 hours (two hourly runs), and run on at most 3 hosts before that.
| WHERE first_seen >= NOW() - 2 hours AND baseline_hosts <= 3
| KEEP host.id, host.name, pname, baseline_hosts, first_seen, last_seen, runs, users, parents, exe, cmd, sha256
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 7 days:
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
// Anchor: a remote-management or tunnelling tool starts, matched by file name.
| in(field="FileName", ignoreCase=true, values=["anydesk.exe", "screenconnect.clientservice.exe", "screenconnect.windowsclient.exe",
                                                "connectwisecontrol.client.exe", "ateraagent.exe", "splashtop_streamer.exe", "rustdesk.exe",
                                                "teamviewer.exe", "teamviewerqs.exe", "quickassist.exe", "logmein.exe", "gotoassist.exe",
                                                "supremo.exe", "ammyy.exe", "ultraviewer_desktop.exe", "zohoassist.exe", "meshagent.exe",
                                                "syncro.exe", "dwagent.exe", "rport.exe", "netsupport.exe", "client32.exe", "remotepc.exe",
                                                "radmin.exe", "ngrok.exe", "cloudflared.exe", "chisel.exe", "ligolo.exe", "ligolo-agent.exe",
                                                "frpc.exe", "bore.exe", "socat.exe", "gost.exe", "tailscale.exe", "zerotier-one.exe",
                                                "psiphon.exe", "tor.exe", "proxifier.exe", "devtunnel.exe"])
| pname := lower(FileName)
// One row per host and tool: when it first ran in the lookback, and what ran.
| groupBy([aid, pname], function=[min(@timestamp, as=first_seen), collect([ComputerName, ImageFileName, CommandLine])], limit=max)
// Hosts where it ran before the last 2 hours are history; hosts where it's new are the candidates.
| _now := now()
| case { test(first_seen < _now - 7200000) | ran_before := aid; * | new_host := aid; }
// One row per tool: alert when it's new somewhere and ran on at most 3 hosts before.
| groupBy([pname], function=[count(ran_before, distinct=true, as=baseline_hosts),
                             collect([new_host, ComputerName, ImageFileName, CommandLine])], limit=max)
| test(baseline_hosts <= 3)
| new_host=*
```
LogScale has no `INLINE STATS`, so this version rolls up to one row per tool: `new_host` lists the hosts where it's new, and the other columns cover every host that ran it (at most three before the last 2 hours, plus the new ones).

Tunnels by behaviour (a renamed ngrok or cloudflared, `ssh`/`plink` `-R`/`-D`, chisel arguments) are fixed-detections 01 After B, and VS Code tunnels are CS13, so they aren't repeated here. `code-tunnel.exe` isn't on the list: the VS Code desktop app runs it for routine status checks.

## Suppression
Suppress by `host.id`, `pname` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: the 7-day lookback overlaps every run, and a tool alerts once per host, when it's new there.

## Known false positives / exclusions
- A tool IT starts using on a few hosts. It alerts on the first three or so, then has a history and stops. Confirm with IT.
- Quick Assist and TeamViewer drop out once they're in regular use. The help-desk scam that abuses them (an external Teams chat, then a remote tool) is X06.

## Blind spot
If your approved RMM is one of the tools on the list, an intruder installing their own copy of the same product isn't caught by name: it has your tool's history. Watch that product's instance or relay ID in its command line instead (ScreenConnect's `h=` relay host, for example). That check is product-specific.

## Triage
- Read `exe`, `parents` and `users`: a tool run from `Downloads` or `Temp`, started by a browser or by a script, on a host that has never had it, is the intrusion pattern.
- Block the tool in Falcon, kill the process, and ask whether a help-desk call or Teams chat came first (X06).

## Test
Run a portable build of an unapproved RMM tool from `%TEMP%` on a lab host, then remove it.
