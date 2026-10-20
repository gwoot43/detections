---
id: CS13
name: VS Code tunnel started on an endpoint (code tunnel, Remote Tunnel Access)
category: crowdstrike-fdr
status: todo
severity: high
language: esql
index: logs-yourorg-crowdstrike-data-default*
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
- `--cli-data-dir`, which the persistent service always passes;
- `tunnel user login`, the step that links the tunnel to the GitHub or Microsoft account its owner connects with. A tunnel is useless without an account, so a renamed copy started from a script still has to log in;
- a binary named `code*` (`code.exe`, `code-tunnel.exe`, `code-insiders.exe`, `code` on Linux);
- an executable in a staging folder: `ProgramData`, `Users\Public` or `Windows\Debug`.

One exclusion: the desktop app runs `code-tunnel.exe tunnel status` on its own. This is the shape of Elastic's prebuilt rule "Attempt to Establish VScode Remote Tunnel". It's adapted to FDR: `tunnel` is matched as a whole word in the command line, the name test also covers Linux, and `--cli-data-dir` and `tunnel user login` stand in for Elastic's signer test, which FDR can't do. A renamed CLI alerts when it logs in, and again at every logon once it's installed as a service.

## Query
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action IN ("processrollup2", "syntheticprocessrollup2")
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, "")), pname = TO_LOWER(COALESCE(process.name, "")),
       exe = TO_LOWER(COALESCE(process.executable, "")), parent = TO_LOWER(COALESCE(process.parent.name, ""))
// Anchor: "tunnel" as an argument of its own, which every VS Code tunnel action passes.
| WHERE cmd RLIKE ".* tunnel( .*)?"
  // Corroborating property, any one: the licence flag unattended starts need, the flag the persistent service passes,
  // the account login every tunnel needs, a code* binary, or a copy in a staging folder
  // (FDR paths start \Device\HarddiskVolumeN\, so match from the folder down)
  AND (cmd LIKE "*--accept-server-license-terms*" OR cmd LIKE "*--cli-data-dir*" OR cmd LIKE "*tunnel user login*"
       OR pname LIKE "code*"
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
// Anchor: "tunnel" as an argument of its own, which every VS Code tunnel action passes.
| CommandLine=/ tunnel( |$)/i
// Corroborating property, any one: the licence or service flag, the account login, a code* binary, or a copy in a staging folder.
| case {
    CommandLine=/--accept-server-license-terms|--cli-data-dir|tunnel user login/i;
    FileName=/^code/i;
    ImageFileName=/\\(programdata|users\\public|windows\\debug)\\/i;
  }
// the desktop app checks tunnel status on its own
| NOT (FileName=/^code-tunnel/i AND ParentBaseFileName=/^code/i AND CommandLine=/ status( |$)/i)
| !in(field="aid", values=["<approved_tunnel_host_aid>"])
| select([@timestamp, aid, ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName, TargetProcessId])
```

## Suppression
Suppress by `host.id` for 24h. Alerts missing a key field are not suppressed. One tunnel produces several processes (login, start, service install). An installed tunnel starts at every logon, so a tunnel left in place keeps alerting daily until it's removed.

## Known false positives / exclusions
- Developers approved to use Remote Tunnels. Add their hosts' Falcon agent IDs to the placeholder list; exclude by host, not by user, so the same account starting a tunnel on a server still alerts.
- Another tool that takes `tunnel` as an argument (`cloudflared tunnel`) only matches when it runs from a staging folder. That's still a tunnel worth the alert.

## Blind spot
Elastic's rule also matches a renamed CLI by its Microsoft signature. FDR process events carry no signer name, so a renamed copy is matched by what it does instead: `tunnel user login`, the licence flag a scripted start needs, or `--cli-data-dir` once it's a service. What's left is a renamed copy, outside the staging folders, started by hand with plain `tunnel` and logged in at its interactive prompt rather than through `user login`, then never installed as a service. The Zscaler view of the relay domains (fixed-detections 01 After A) still sees that tunnel.

## Triage
- Read the command line. `--name` is the tunnel's name (reachable at `vscode.dev/tunnel/<name>`). On `tunnel user login`, `--provider` says which account type it was linked to (`github` or `microsoft`). `--access-token <token>` puts a live token in the command line and in your logs: revoke it.
- A login from the desktop app (parent `code.exe`, binary `code-tunnel.exe`) is a user turning on Remote Tunnel Access from the menu. A login from `cmd`, PowerShell, a script host or a renamed binary is someone setting a tunnel up by hand.
- Was it used? Find the tunnel's child processes (`process.parent.entity_id` equal to this event's `process.entity_id`). A VS Code server (`code-server`, `node`) starting under it means someone connected; shells under that server are commands typed through the tunnel.
- `tunnel service install` makes it persistent: an HKCU `Run` value on Windows (CS02), a systemd user unit `code-tunnel.service` on Linux, a launchd agent `com.visualstudio.code.tunnel` on macOS. Find the owning account with `<cli> tunnel user show`. If the user can't explain it, isolate the host, then remove it with `<cli> tunnel service uninstall` and `<cli> tunnel unregister`.

## Test
On a lab host, download the standalone VS Code CLI and run `code.exe tunnel user login --provider github`, then `code.exe tunnel --accept-server-license-terms --name lab-test`. Then copy it to `C:\ProgramData\updater.exe` and run `updater.exe tunnel`, and copy it to `%LOCALAPPDATA%\helper.exe` and run `helper.exe tunnel user login --provider github`. Each should alert. Opening the VS Code desktop app, which runs `code-tunnel.exe tunnel status`, should not. Clean up with `tunnel service uninstall` and `tunnel unregister`.
