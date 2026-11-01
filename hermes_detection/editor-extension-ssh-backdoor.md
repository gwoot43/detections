# Editor extension spawning a reverse SSH tunnel

In October 2026 a trojanised copy of the Claude Code extension (`anthropic.claude-code` 2.1.312/2.1.313) was served from the Cursor marketplace. Its injected loader ran before the extension's own code, appended an attacker's Ed25519 key to `authorized_keys`, then started a **reverse SSH forward** so the attacker's server could dial back into the workstation's port 22. It also wrote persistence - a `@reboot` crontab entry on Linux, a Startup folder batch file and a scheduled task named `SysMon` on Windows.

Two things make this detectable without naming any file, key or task:

**A tunnel is not a session.** `ssh -N -R` asks the *server* for a listening port and forwards it back to the local machine, with no command to run. Nothing an interactive administrator does looks like that, and the flags that come with it - host-key checking disabled, `known-hosts` bypassed, batch mode, keepalives - are the ones a loader needs to stay silent.

**The parent gives it away.** A human launches `ssh` from a terminal. An extension launches it from the editor's extension host (`node`, `Cursor Helper`, `extensionHost`), and the retry loop relaunches it from a hidden PowerShell or shell loop every 60 seconds.

```esql
FROM logs-yourorg-crowdstrike-data-default*
// 15 minutes, stated in the query: the loop relaunches every 60 seconds, so the window only needs to be
// longer than one retry.
| WHERE @timestamp >= NOW() - 15 minutes
  AND event.action IN ("processrollup2", "syntheticprocessrollup2")
| EVAL proc = TO_LOWER(COALESCE(process.name, "")),
       cl = TO_LOWER(COALESCE(process.command_line, "")),
       parent = TO_LOWER(COALESCE(process.parent.name, "")),
       origin = TO_LOWER(COALESCE(process.parent.executable, ""))
// -R is the reverse forward; -N is "run no command", which is what makes it a tunnel rather than a session.
// autossh exists only to keep a tunnel alive, so it counts as -N even when the flag is spelled differently.
| EVAL reverse_tunnel = (proc IN ("ssh", "ssh.exe", "autossh", "autossh.exe") OR cl LIKE "*autossh*")
                       AND (cl LIKE "*-r *" OR cl LIKE "*-r=*")
                       AND (cl LIKE "*-n *" OR cl LIKE "*autossh*")
// The flags a loader needs: no known_hosts, no prompt, no host-key verification, keepalives on.
| EVAL blind = cl LIKE "*stricthostkeychecking=no*" OR cl LIKE "*userknownhostsfile=/dev/null*"
              OR cl LIKE "*userknownhostsfile=nul*" OR cl LIKE "*batchmode=yes*"
              OR cl LIKE "*serveraliveinterval*",
// The parent is the other half: an editor's extension host, or a shell loop the loader started.
       from_editor = parent IN ("node", "node.exe", "code", "code.exe", "cursor", "cursor.exe",
                                "electron", "electron.exe", "code helper (plugin)", "extensionhost")
                     OR origin LIKE "*cursor*" OR origin LIKE "*visual studio code*"
| WHERE reverse_tunnel AND (blind OR from_editor)
| STATS launches = COUNT(*),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        cmd = MV_SLICE(VALUES(process.command_line), 0, 3),
        parents = MV_SLICE(VALUES(process.parent.name), 0, 3),
        parent_path = MV_SLICE(VALUES(process.parent.executable), 0, 2),
        users = MV_SLICE(VALUES(user.name), 0, 3)
    BY host.id, host.name
| SORT launches DESC
| LIMIT 100
```

Deploy every 5 minutes over the last 15. Suppress by `host.id` for 24h.

## Reading the alert
- **`launches`** above 1 in a quarter hour is the retry loop, not a person. A single launch with an editor parent is the first attempt.
- **`cmd`** shows the forward spec: `-r '*:0:localhost:22'` is the Cursor loader exactly - a server-assigned port forwarded to the workstation's own SSH. A `-r 0:localhost:22` form is the same thing spelled differently.
- **`parent_path`** is the evidence: an extension host under `%USERPROFILE%\.cursor\extensions\` or `~/.cursor/extensions/` names the package, and the package version is the whole incident.
- **`users`** on Windows will usually be the logged-on user, not SYSTEM - the loader is not privileged, which is why it also writes per-user persistence.

## What it misses
- **The failure case.** The loader plants the key and persistence even when the tunnel never comes up (privileges, server config). This rule sees only the tunnel attempt, so the persistence has to come from the registry and scheduled-task rules - and on Linux, from a `@reboot` crontab entry that needs file or audit telemetry this feed does not carry.
- **A renamed or vendored `ssh`** (a bundled `plink.exe`, a statically-linked client inside the extension). The `-R`/`-N` shape survives the binary rename only if the arguments do; a wrapper that builds the arguments differently is invisible.
- **Interactive sessions.** `ssh user@host` with a command, `sftp`, `scp` and port forwards in the other direction (`-L`) are deliberately not matched - they are how administrators work.
- **An attacker who uses the planted key rather than the tunnel** - that is a logon, and belongs to the identity rules.

## IOC sweep for this incident
Plain indicators, no detection logic - useful while the incident is fresh, and useless the moment the family renames its files:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 30 days
| EVAL cl = TO_LOWER(COALESCE(process.command_line, ""))
| WHERE cl LIKE "*svc-telemetry*" OR cl LIKE "*.stk_*" OR cl LIKE "*/.config/.smt*"
     OR cl LIKE """*\\.config\\smt.cmd*""" OR cl LIKE """*\\.config\\smtk*"""
     OR cl LIKE """*startup\\sysmon.cmd*"""
| STATS hits = COUNT(*), first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        cmd = MV_SLICE(VALUES(process.command_line), 0, 3)
    BY host.id, host.name
| SORT hits DESC
```
`svc-telemetry` is the comment on the planted `authorized_keys` entry, `.stk_` plus ten hex characters is the temporary private key, `.smt`/`.smtk` are the persistence script and identity, and `sysmon.cmd` in Startup is the Windows fallback.

## Nearest benign twins
- **Remote development and tunnelling products** built into editors (VS Code Remote-SSH, JetBrains Gateway, `code tunnel`), which do run SSH from an extension host. They use their own `sshd` path and a config file rather than `-R ... localhost:22` with host-key checking off; if your developers use them heavily, exclude the specific binary path as an entity pair rather than the whole parent.
- **Support tools** that build reverse tunnels to a vendor's jump host (some RMM agents do exactly this). They are signed, installed, and run as a service - the parent is `services.exe`, not an editor.
- **A developer's own `autossh -M 0 -N -R`** to reach a home lab. Rare, and it looks identical by design; it needs the entity pair exclusion and a conversation with the developer.

## Verify before enabling
`process.parent.name` and `process.parent.executable` must be populated on this pipeline, or the editor half of the condition never fires:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 1 hour
  AND event.action IN ("processrollup2", "syntheticprocessrollup2")
| STATS events = COUNT(*), with_parent = COUNT(*) WHERE process.parent.name IS NOT NULL,
        with_parent_path = COUNT(*) WHERE process.parent.executable IS NOT NULL
```
If `with_parent_path` is zero, drop it from the condition and rely on `process.parent.name` alone. Check Linux coverage the same way - `host.os.type` should report both operating systems:
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 24 hours AND event.action == "processrollup2"
| STATS events = COUNT(*) BY host.os.type
```

## References
- Microsoft Threat Intelligence, *Inside a malicious Claude Code-branded extension and its persistent SSH backdoor* (30 Oct 2026) - the injected loader, the `-N -R '*:0:localhost:22'` command line, the `svc-telemetry` key comment, and the persistence artefacts: `microsoft.com/en-us/security/blog/2026/10/30/inside-malicious-claude-code-branded-cursor-extension-persistent-ssh-backdoor/`
- Cursor, security notice for the extension incident (`cursor.com/blog/claude-code-extension-security-notice`) - affected versions 2.1.312/2.1.313 and the removal steps
- MITRE T1572 (protocol tunnelling), T1547/T1053 (persistence), T1098.004 (SSH authorized keys)
- `rules/07-crowdstrike-fdr/CS02` and `CS07` for the Windows persistence halves; `hermes_detection/registry-writes-that-matter.md` and `scheduled-task-that-matters.md` for the versions that do not alert on every write
