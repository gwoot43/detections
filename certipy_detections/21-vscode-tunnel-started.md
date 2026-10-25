---
id: TUNNEL-01
name: VS Code tunnel started on an endpoint (code tunnel / Remote Tunnel Access used as C2)
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1219.001, T1572]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
**Catches:** `code tunnel` run on a host. It makes the host reachable from anywhere through Microsoft's dev-tunnels relay - whoever owns the linked GitHub/Microsoft account gets a terminal and the filesystem from vscode.dev, with no inbound firewall rule. Intruders use it as C2 because it's a signed Microsoft binary talking outbound HTTPS to a Microsoft domain.

Ported from the library's CS13 (the highest-fidelity VS Code tunnel rule), condensed for this folder. One anchor, one corroborating property - not a list of command variants:

- **Anchor:** `tunnel` as an argument of its own. Every tunnel action passes it, including the persistent service.
- **Corroborating, any one:** `--accept-server-license-terms` (unattended starts need it), `--cli-data-dir` (the persistent service always passes it), `tunnel user login` (a tunnel is useless without an account, so a renamed copy still logs in), a `code*` binary, or an executable run from a staging folder (`ProgramData`, `Users\Public`, `Windows\Debug`).

FDR carries no signer name, so a renamed CLI is matched by what it does (the login, the licence flag, `--cli-data-dir`) rather than by Microsoft's signature.

Run every 15 minutes over the last hour.
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action IN ("processrollup2", "syntheticprocessrollup2")
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, "")), pname = TO_LOWER(COALESCE(process.name, "")),
       exe = TO_LOWER(COALESCE(process.executable, "")), parent = TO_LOWER(COALESCE(process.parent.name, ""))
// Anchor: "tunnel" as an argument of its own, which every VS Code tunnel action passes.
| WHERE cmd RLIKE ".* tunnel( .*)?"
  // Corroborating property, any one: the licence/service flag, the account login, a code* binary, or a staging-folder copy
  AND (cmd LIKE "*--accept-server-license-terms*" OR cmd LIKE "*--cli-data-dir*" OR cmd LIKE "*tunnel user login*"
       OR pname LIKE "code*"
       OR exe LIKE """*\\programdata\\*""" OR exe LIKE """*\\users\\public\\*""" OR exe LIKE """*\\windows\\debug\\*""")
  // the desktop app checks tunnel status on its own
  AND NOT (pname LIKE "code-tunnel*" AND parent LIKE "code*" AND cmd RLIKE ".* status( .*)?")
  // hosts approved to run VS Code tunnels (placeholder: Falcon agent IDs)
  AND NOT host.id IN ("<approved_tunnel_host_aid>")
| KEEP @timestamp, host.id, host.name, user.name, process.executable, process.command_line, process.parent.name,
       process.entity_id, _id, _index, _version
```

**CrowdStrike (Falcon LogScale)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/
// Anchor: "tunnel" as an argument of its own, which every VS Code tunnel action passes.
| CommandLine=/ tunnel( |$)/i
// Corroborating property, any one: the licence/service flag, the account login, a code* binary, or a staging-folder copy.
// Deliberately no * branch: this case is the filter.
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
Suppress by host for 24h. An installed tunnel starts at every logon, so a tunnel left in place keeps alerting daily until it's removed.

## What it catches and what it doesn't
- **Caught:** `code tunnel` however it's started - the desktop app's Remote Tunnel Access, the standalone CLI, or a renamed copy (by its login/licence/service flags or its staging-folder path).
- **Not caught here:** a renamed copy, outside the staging folders, started by hand with a bare `tunnel` and logged in at its interactive prompt (not `tunnel user login`), never installed as a service. The Zscaler view of the relay domains still sees that one.
- **Separate tool:** `cloudflared tunnel` only matches when it runs from a staging folder - still a tunnel worth the alert.

## When it fires
Read the command line: `--name` is the tunnel's name (reachable at `vscode.dev/tunnel/<name>`), `--provider` the account type, `--access-token <token>` a live token in your logs - revoke it. A login from `cmd`/PowerShell/a script host or a renamed binary is someone setting a tunnel up by hand (a login from `code.exe` is a user turning it on). Find the tunnel's children (`process.parent.entity_id` = this event's `process.entity_id`): a `code-server`/`node` under it means someone connected; shells under that are commands typed through the tunnel. `tunnel service install` makes it persistent (CS02 on Windows) - remove with `tunnel service uninstall` and `tunnel unregister`.
