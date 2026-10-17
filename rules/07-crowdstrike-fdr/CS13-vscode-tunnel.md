---
id: CS13
name: VS Code tunnel started on an endpoint (code tunnel, Remote Tunnel Access)
category: crowdstrike-fdr
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1219.001, T1572]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
`code tunnel` makes a host reachable from anywhere through Microsoft's dev tunnels relay. Whoever owns the linked GitHub or Microsoft account gets a terminal and file access from vscode.dev. On the wire it's outbound HTTPS to a Microsoft domain from a Microsoft-signed binary, with no inbound firewall rule, and intruders have used it as a C2 channel. The proxy only sees the domain; the endpoint sees the process.

The rule has one anchor and one corroborating property, not a list of command variants. The anchor is `tunnel` as an argument of its own. Every tunnel action passes it, including the persistent service (`--cli-data-dir <dir> tunnel service internal-run`). It must come with one of:
- `--accept-server-license-terms`, which unattended starts need;
- a binary named `code*` (`code.exe`, `code-tunnel.exe`, `code-insiders.exe`, `code` on Linux);
- an executable in a staging folder: `ProgramData`, `Users\Public` or `Windows\Debug`.

One exclusion: the desktop app runs `code-tunnel.exe tunnel status` on its own. This is the shape of Elastic's prebuilt rule "Attempt to Establish VScode Remote Tunnel". It's adapted to FDR: `tunnel` is matched as a whole word in the command line, and the name test also covers Linux.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action IN ("ProcessRollup2", "SyntheticProcessRollup2")
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, "")), pname = TO_LOWER(COALESCE(process.name, "")),
       exe = TO_LOWER(COALESCE(process.executable, "")), parent = TO_LOWER(COALESCE(process.parent.name, ""))
| WHERE cmd RLIKE ".* tunnel( .*)?"
  AND (cmd LIKE "*--accept-server-license-terms*"
       OR pname LIKE "code*"
       // FDR paths start \Device\HarddiskVolumeN\, so match from the folder down
       OR exe LIKE """*\\programdata\\*""" OR exe LIKE """*\\users\\public\\*""" OR exe LIKE """*\\windows\\debug\\*""")
  // the desktop app checks tunnel status on its own
  AND NOT (pname LIKE "code-tunnel*" AND parent LIKE "code*" AND cmd RLIKE ".* status( .*)?")
  // hosts approved to run VS Code tunnels (placeholders: Falcon agent IDs)
  AND NOT host.id IN ("<approved_tunnel_host_aid>")
| KEEP @timestamp, host.id, host.name, user.name, process.executable, process.command_line, process.parent.name,
       process.entity_id, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/
| CommandLine=/ tunnel( |$)/i
| case {
    CommandLine=/--accept-server-license-terms/i;
    FileName=/^code/i;
    ImageFileName=/\\(programdata|users\\public|windows\\debug)\\/i;
  }
// the desktop app checks tunnel status on its own
| NOT (FileName=/^code-tunnel/i AND ParentBaseFileName=/^code/i AND CommandLine=/ status( |$)/i)
| !in(field="aid", values=["<approved_tunnel_host_aid>"])
| table([@timestamp, aid, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName, TargetProcessId])
```

## Suppression
Suppress by `host.id` for 24h. Alerts missing a key field are not suppressed. One tunnel produces several processes (login, start, service install). An installed tunnel starts at every logon, so a tunnel left in place keeps alerting daily until it's removed.

## Known false positives / exclusions
- Developers approved to use Remote Tunnels. Add their hosts' Falcon agent IDs to the placeholder list; exclude by host, not by user, so the same account starting a tunnel on a server still alerts.
- Another tool that takes `tunnel` as an argument (`cloudflared tunnel`) only matches when it runs from a staging folder. That's still a tunnel worth the alert.

## Blind spot
Elastic's rule also matches a renamed CLI by its Microsoft signature. FDR process events carry no signer name, so a renamed CLI run outside the staging folders without the licence flag isn't matched. On its first run from a script the CLI needs the flag, so a fresh, unattended install is still caught. The Zscaler view of the relay domains (fixed-detections 01 After A) still sees the tunnel itself.

## Triage
- Read the command line. `--name` is the tunnel's name (reachable at `vscode.dev/tunnel/<name>`) and `--provider` is `github` or `microsoft`. `user login --access-token <token>` puts a live token in the command line and in your logs: revoke it.
- Was it used? Find the tunnel's child processes (`process.parent.entity_id` equal to this event's `process.entity_id`). A VS Code server (`code-server`, `node`) starting under it means someone connected; shells under that server are commands typed through the tunnel.
- `tunnel service install` makes it persistent: an HKCU `Run` value on Windows (CS02), a systemd user unit `code-tunnel.service` on Linux, a launchd agent `com.visualstudio.code.tunnel` on macOS. Find the owning account with `<cli> tunnel user show`. If the user can't explain it, isolate the host, then remove it with `<cli> tunnel service uninstall` and `<cli> tunnel unregister`.

## Test
On a lab host, download the standalone VS Code CLI and run `code.exe tunnel --accept-server-license-terms --name lab-test`. Then copy it to `C:\ProgramData\updater.exe` and run `updater.exe tunnel`. Each should alert. Opening the VS Code desktop app, which runs `code-tunnel.exe tunnel status`, should not. Clean up with `tunnel service uninstall` and `tunnel unregister`.
