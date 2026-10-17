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
Ransomware affiliates and help-desk social engineering crews drop a second RMM tool or a tunnel for persistence and C2. You have one approved RMM. Everything else on the list, especially from a user-writable path, is an intrusion or shadow IT that must go.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL pname = TO_LOWER(process.name), exe = TO_LOWER(COALESCE(process.executable, ""))
| WHERE pname IN ("anydesk.exe", "screenconnect.clientservice.exe", "screenconnect.windowsclient.exe", "connectwisecontrol.client.exe", "ateraagent.exe",
                  "splashtop_streamer.exe", "rustdesk.exe", "teamviewer.exe", "teamviewerqs.exe", "quickassist.exe",
                  "logmein.exe", "gotoassist.exe", "supremo.exe", "ammyy.exe", "ultraviewer_desktop.exe", "zohoassist.exe", "meshagent.exe", "syncro.exe", "dwagent.exe", "rport.exe", "netsupport.exe", "client32.exe", "remotepc.exe", "radmin.exe",
                  "ngrok.exe", "cloudflared.exe", "chisel.exe", "ligolo.exe", "ligolo-agent.exe", "frpc.exe", "bore.exe", "socat.exe", "gost.exe", "tailscale.exe", "zerotier-one.exe", "psiphon.exe", "tor.exe", "proxifier.exe")
// remove your own approved tool from the list, then keep this guard for its install path.
// FDR records executables as \Device\HarddiskVolumeN\..., never C:\..., so match from the folder down.
| WHERE NOT (exe LIKE """*\\program files\\your-approved-rmm\\*""")
| KEEP @timestamp, host.id, host.name, user.name, process.parent.name, pname, exe, process.command_line, process.hash.sha256, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
| in(field="FileName", ignoreCase=true, values=["anydesk.exe", "screenconnect.clientservice.exe", "screenconnect.windowsclient.exe",
                                                "connectwisecontrol.client.exe", "ateraagent.exe", "splashtop_streamer.exe", "rustdesk.exe",
                                                "teamviewer.exe", "teamviewerqs.exe", "quickassist.exe", "logmein.exe", "gotoassist.exe",
                                                "supremo.exe", "ammyy.exe", "ultraviewer_desktop.exe", "zohoassist.exe", "meshagent.exe",
                                                "syncro.exe", "dwagent.exe", "rport.exe", "netsupport.exe", "client32.exe", "remotepc.exe",
                                                "radmin.exe", "ngrok.exe", "cloudflared.exe", "chisel.exe", "ligolo.exe", "ligolo-agent.exe",
                                                "frpc.exe", "bore.exe", "socat.exe", "gost.exe", "tailscale.exe", "zerotier-one.exe",
                                                "psiphon.exe", "tor.exe", "proxifier.exe"])
// remove your own approved tool from the list, then keep this guard for its install path.
// FDR records executables as \Device\HarddiskVolumeN\..., never C:\..., so match from the folder down.
| NOT ImageFileName=/\\program files\\your-approved-rmm\\/i
| table([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, ImageFileName, CommandLine, SHA256HashData])
```
This rule matches tools by name. Tunnels by behaviour (a renamed ngrok or cloudflared, `ssh`/`plink` `-R`/`-D`, chisel arguments) are fixed-detections 01 After B, and VS Code and dev tunnels are CS13, so they aren't repeated here. `code-tunnel.exe` isn't on the list: the VS Code desktop app runs it for routine status checks.

`quickassist.exe` and `teamviewer.exe` will be noisy if IT uses them. Decide once, then either remove them or restrict to launches under user-writable paths.

## Suppression
Suppress by `host.id`, `pname` for 24h. Alerts missing a key field are not suppressed. Remote access agents restart constantly. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- Your own RMM, VPN client and sanctioned developer tunnelling. Remove from the list rather than exclude.
- Browser launches that carry a `trycloudflare.com` or `devtunnels.ms` link are not matched; this rule is about running the tunnel, not visiting one.

## Triage
- Block the tool in Falcon, kill the process, review who installed it and whether a help-desk call preceded it.

## Test
Run a portable build of an unapproved RMM tool from `%TEMP%` on a lab host, then remove it.
