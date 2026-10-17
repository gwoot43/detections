---
id: CS13
name: VS Code or dev tunnel opened on an endpoint (code tunnel, Remote Tunnel Access, devtunnel host)
category: crowdstrike-fdr
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1219.001, T1572]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, finding]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
`code tunnel` makes a host reachable from anywhere through Microsoft's dev tunnels relay. Whoever owns the linked GitHub or Microsoft account gets a terminal and file access from vscode.dev. On the wire it's outbound HTTPS to a Microsoft domain from a Microsoft-signed binary, with no inbound firewall rule, and intruders have used it as a C2 channel. The proxy only sees the domain; the endpoint sees the command.

The rule matches the command line, not the file name. The standalone VS Code CLI is a single `code.exe` (or `code`) that can be copied anywhere and renamed, but the arguments that start a tunnel are specific to VS Code:
- `tunnel ... --accept-server-license-terms` starts a tunnel host without the licence prompt. Scripts need it, and so does the desktop app's Remote Tunnel Access.
- `tunnel service install` makes the tunnel persistent: an HKCU `Run` value on Windows, a systemd user unit `code-tunnel.service` on Linux, a launchd agent `com.visualstudio.code.tunnel` on macOS. The persistent tunnel then runs as `--cli-data-dir <dir> tunnel service internal-run` at every logon.
- `tunnel user login` links the tunnel to an account.
- `tunnel forward-internal` (hidden) forwards local ports through a dev tunnel.
- A binary named `code`, `code-tunnel` or `code-insiders` running `tunnel` with only options after it: a tunnel started from a terminal after the licence was accepted once.
- `devtunnel host`: Microsoft's dev tunnels CLI, same relay.

Management subcommands (`tunnel status`, `kill`, `prune`, `rename`, `user show`) don't match. The desktop app runs `code-tunnel.exe tunnel status` routinely, which is why matching `code-tunnel.exe` by name alone is noisy. Connecting *to* someone else's tunnel (`--remote tunnel+name`, or vscode.dev in a browser) isn't hosting one and isn't matched; the relay domains in Zscaler are fixed-detections 01 After A.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action IN ("ProcessRollup2", "SyntheticProcessRollup2")
  // hosts approved to run VS Code or dev tunnels (placeholders: Falcon agent IDs)
  AND NOT host.id IN ("<approved_tunnel_host_aid>")
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, "")), pname = TO_LOWER(COALESCE(process.name, ""))
| EVAL finding = CASE(
    cmd LIKE "* tunnel *" AND cmd LIKE "*service install*", "tunnel service installed",
    cmd LIKE "* tunnel *" AND cmd LIKE "*service internal-run*", "tunnel service running",
    cmd LIKE "* tunnel*" AND cmd LIKE "*--accept-server-license-terms*", "tunnel host started",
    cmd LIKE "* tunnel *" AND cmd LIKE "*user login*", "tunnel account login",
    cmd LIKE "* tunnel forward-internal*", "port forwarded through a dev tunnel",
    // the CLI by name, "tunnel" followed by options only (no status, kill, user show...)
    pname IN ("code.exe", "code-tunnel.exe", "code-insiders.exe", "code-tunnel-insiders.exe", "code", "code-tunnel", "code-insiders")
      AND cmd RLIKE """.* tunnel( --[^ ]+( [^ ]+)?)* *""", "tunnel host started",
    pname IN ("devtunnel.exe", "devtunnel") AND cmd LIKE "* host*", "dev tunnel host started",
    NULL)
| WHERE finding IS NOT NULL
| KEEP @timestamp, host.id, host.name, user.name, finding, process.executable, process.command_line, process.parent.name,
       process.entity_id, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/
| !in(field="aid", values=["<approved_tunnel_host_aid>"])
| cmd := lower(CommandLine)
| pname := lower(FileName)
| case {
    cmd=/ tunnel / cmd=/service install/                 | finding := "tunnel service installed";
    cmd=/ tunnel / cmd=/service internal-run/            | finding := "tunnel service running";
    cmd=/ tunnel/ cmd=/--accept-server-license-terms/    | finding := "tunnel host started";
    cmd=/ tunnel / cmd=/user login/                      | finding := "tunnel account login";
    cmd=/ tunnel forward-internal/                       | finding := "port forwarded through a dev tunnel";
    // the CLI by name, "tunnel" followed by options only (no status, kill, user show...)
    in(field="pname", values=["code.exe", "code-tunnel.exe", "code-insiders.exe", "code-tunnel-insiders.exe", "code", "code-tunnel", "code-insiders"])
      cmd=/ tunnel( --[^ ]+( [^ ]+)?)* *$/               | finding := "tunnel host started";
    in(field="pname", values=["devtunnel.exe", "devtunnel"]) cmd=/ host/ | finding := "dev tunnel host started";
  }
| table([@timestamp, aid, ComputerName, UserName, finding, ImageFileName, CommandLine, ParentBaseFileName, TargetProcessId])
```

The branches are checked in order, so a service install that also carries the licence flag is labelled as the install.

## Suppression
Suppress by `host.id`, `finding` for 24h. Alerts missing a key field are not suppressed. A tunnel start, its login and its service install each alert once per host per day. An installed service starts at every logon, so a tunnel left in place keeps alerting daily until it's removed.

## Known false positives / exclusions
- Developers approved to use Remote Tunnels or port forwarding. Add their hosts' Falcon agent IDs to the placeholder list; exclude by host, not by user, so the same account starting a tunnel on a server still alerts.
- A renamed CLI started with plain `tunnel`, without the licence flag, isn't matched. That only works where the licence was already accepted in the same CLI data folder; a first run from a script needs the flag.

## Triage
- Read the command line. `--name` is the tunnel's name (reachable at `vscode.dev/tunnel/<name>`) and `--provider` is `github` or `microsoft`. `user login --access-token <token>` puts a live token in the command line and in your logs: revoke it.
- Was it used? Find the tunnel's child processes (`process.parent.entity_id` equal to this event's `process.entity_id`). A VS Code server (`code-server`, `node`) starting under it means someone connected; shells under that server are commands typed through the tunnel.
- Which account owns it: run `<cli> tunnel user show` on the host. If the user can't explain it, isolate the host, then remove it with `<cli> tunnel service uninstall` and `<cli> tunnel unregister`, and check the HKCU `Run` key (CS02) for a leftover value.
- Zscaler: the same user's traffic to `global.rel.tunnels.api.visualstudio.com` shows when the tunnel was live (fixed-detections 01 After A).

## Test
On a lab host, download the standalone VS Code CLI, rename it `updater.exe` and run `updater.exe tunnel --accept-server-license-terms --name lab-test`. Then run `updater.exe tunnel service install`. Each should alert once. Opening the VS Code desktop app, which runs `code-tunnel.exe tunnel status`, should not. Clean up with `updater.exe tunnel service uninstall` and `updater.exe tunnel unregister`.
