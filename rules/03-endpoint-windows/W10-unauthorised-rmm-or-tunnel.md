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
---
## Why this is high fidelity
Ransomware affiliates and help-desk social engineering crews drop a second RMM tool or a tunnel for persistence and C2. You have one approved RMM. Everything else on the list, especially from a user-writable path, is an intrusion or shadow IT that must go.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "windows"
| EVAL pname = TO_LOWER(process.name), exe = TO_LOWER(process.executable), cmd = TO_LOWER(process.command_line)
| WHERE pname IN ("anydesk.exe", "screenconnect.clientservice.exe", "screenconnect.windowsclient.exe", "connectwisecontrol.client.exe", "ateraagent.exe",
                  "splashtop_streamer.exe", "rustdesk.exe", "teamviewer.exe", "teamviewerqs.exe", "quickassist.exe",
                  "logmein.exe", "gotoassist.exe", "supremo.exe", "ammyy.exe", "ultraviewer_desktop.exe", "zohoassist.exe", "meshagent.exe", "syncro.exe", "dwagent.exe", "rport.exe", "netsupport.exe", "client32.exe", "remotepc.exe", "radmin.exe",
                  "ngrok.exe", "cloudflared.exe", "chisel.exe", "plink.exe", "ligolo.exe", "ligolo-agent.exe", "frpc.exe", "bore.exe", "socat.exe", "gost.exe", "tailscale.exe", "zerotier-one.exe", "psiphon.exe", "tor.exe", "proxifier.exe", "devtunnel.exe", "code-tunnel.exe")
   OR cmd LIKE "*ngrok*tcp*" OR cmd LIKE "*cloudflared*tunnel*" OR cmd LIKE "*trycloudflare*"
   OR (pname IN ("plink.exe", "ssh.exe") AND (cmd LIKE "* -r *" OR cmd LIKE "* -d *"))
   OR cmd LIKE "*tunnel --accept-server-license-terms*" OR cmd LIKE "*devtunnels*"
// remove your own approved tool from the list, then keep this guard for install path
| WHERE NOT (exe LIKE "c:\\program files\\your-approved-rmm\\*")
| KEEP @timestamp, host.name, user.name, process.parent.name, pname, exe, process.command_line, process.hash.sha256
```
`quickassist.exe` and `teamviewer.exe` will be noisy if IT uses them. Decide once, then either remove them or restrict to launches under user-writable paths.

## Known false positives / exclusions
- Your own RMM, VPN client and sanctioned developer tunnelling. Remove from the list rather than exclude.

## Triage
- Block the tool in Falcon, kill the process, review who installed it and whether a help-desk call preceded it.

## Test
Run a portable RMM installer from `%TEMP%` on a lab host.
