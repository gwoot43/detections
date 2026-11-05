---
id: CS24
name: External SSH tunnels — before and after
category: crowdstrike-fdr
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1071, T1105, T1572]
data_source: CrowdStrike FDR / Windows Security events
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
The original rule watched Falcon process events for `ssh`/`plink` carrying `-R` or `-D` and kept the ones aimed at a destination outside the corporate suffixes. The shape was right. This file records what it was, what was wrong with it, and what it is now - the "before" is kept because three of the fixes are about things that were nearly right.

## Before

Kept as it was written, including the `%` wildcards - ES|QL reads `%` as a literal percent sign, so every
one of those patterns matched nothing. That is defect one in the list below; the rest of the file is the fix.

```text
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action == "processrollup2"
  AND process.command_line IS NOT NULL
  AND process.executable IS NOT NULL
| EVAL exe = TO_LOWER(process.executable), cmd = TO_LOWER(process.command_line)
| WHERE (exe LIKE "*/ssh.exe" OR exe LIKE "*/plink.exe" OR exe LIKE "*/ssh" OR exe LIKE "*/plink")
// -R or -D, incl. combined flags (-NfR, -fND1080); case-sensitive: -r/-d mean something else
  AND <flag test - not legible in the source screenshot>
// Developer devbox instances: sanctioned and used fleet-wide
  AND NOT cmd LIKE "%devbox%"
// Destination: prefer user@host, else first dotted hostname/IP token after a space.
// Explicit char classes, not (?<HOSTNAME>): it stops at ... user@remote server.com "remote
| GROK process.command_line "%{USERNAME:ssh_user}@(?<dest_at>[A-Za-z0-9.-]+)"
| GROK process.command_line "(?<dest_dotted>(?:[A-Za-z0-9_-]+(?:\\.[A-Za-z0-9-]+)+)(?:\\s|$))"
| EVAL dest = TO_LOWER(COALESCE(dest_at, dest_dotted))
// External only: drop unparsed, dotless short names / ssh-config aliases, corporate DNS suffixes, private IPs
| WHERE dest LIKE "%.%"   // also drops null (unparsed) destinations
  AND NOT dest LIKE "%.corp.example"
  AND NOT dest LIKE "%.ad.example"
| EVAL is_ip = dest RLIKE "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
| EVAL is_private = CASE(is_ip, CIDR_MATCH(dest, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                           "127.0.0.0/8", "169.254.0.0/16"), false)
| WHERE NOT is_private
| EVAL destination.domain = dest, ssh.user = ssh_user,
       ssh.tunnel = CASE(..., "socks/dynamic (-D)", ...),
       ssh.egress_port_evasion = ...
| KEEP _id, _index, _version, @timestamp, host.name, user.name, destination.domain, ssh.user, ssh.tunnel,
       ssh.egress_port_evasion, process.executable, process.command_line, process.parent.executable
```

### What was wrong

**`%` instead of `*`.** Every `LIKE` in the rule used SQL wildcards. ES|QL's wildcards are `*` and `?`; `%` is a
literal percent sign, so `dest LIKE "%.%"` matched only a destination containing a percent character. The rule
parsed, linted and returned nothing - which is indistinguishable from a rule that is working and quiet.

**The case-sensitivity contradiction.** `cmd` is `TO_LOWER(process.command_line)`, and the comment above the flag test says the match is case-sensitive because `-r`/`-d` mean something else. Both cannot be true: after lowercasing, `-D` and `-d` are the same string. Whatever the flag test was doing, it was doing it on a value that had already thrown the distinction away.

**Flags that never appear on the command line.** `DynamicForward 1080` or `RemoteForward 8080 localhost:22` written into `~/.ssh/config` produce `ssh host` with no flags at all. The flag test cannot see that, and then `WHERE dest LIKE "*.*"` drops the dotless alias on top of it - two filters pointing the same way, so the quiet case is invisible twice over.

**The dotless drop removes the wrong population.** `ssh tunnel` is exactly what a config-alias backdoor looks like. Dropping unparsed destinations silently is a filter, not a decision.

**IPv6 disappears.** The dotted-quad test means an IPv6 literal never classifies, and `100.64.0.0/10` was missing from the private list - that is Tailscale's range, so a devbox on Tailscale read as external while a genuine IPv6 tunnel read as nothing.

**One launch, one row.** An `autossh` or hidden PowerShell retry loop relaunches every 60 seconds. Without aggregation that is ~1,440 rows per host per day, and the retry loop - which is itself a strong signal - was invisible in the flood.

**Two cheap signals missing.** `-i` pointing outside the key store is the loader shape from the October 2026 Cursor extension incident (`-i /tmp/.stk_xxxxxxxxxx`). And `-o ProxyCommand` is a tunnel through a tunnel, which no flag test will see.

## After

```esql
FROM logs-yourorg-crowdstrike-data-default*
// 15 minutes, stated in the query: a retry loop relaunches every 60 seconds, so one window catches it.
| WHERE @timestamp >= NOW() - 15 minutes
  AND event.action == "processrollup2"
  AND process.command_line IS NOT NULL
  AND process.executable IS NOT NULL
| EVAL exe = TO_LOWER(process.executable),
       cmd = TO_LOWER(process.command_line),
       raw = process.command_line,
// The destination is conventionally the last token, which is also how a config alias arrives: `ssh tunnel`.
       last_token = MV_LAST(SPLIT(TO_LOWER(process.command_line), " ")),
// -R or -D, combined flags included (-NfR, -fND1080), matched on the RAW command line and uppercase only.
// RLIKE is Lucene syntax: no ^ or $ anchors (they are literal), and the whole string is matched implicitly,
// so the flag token is found by requiring a space before it and a space or "=" after it.
// This is the test that has to stay off the lowercased copy: -D and ssh's debug -d, -R and plink's -r, are
// different flags that lowercase into the same string. Computed once here so the gate stays cheap.
       flag = raw RLIKE """.*\s-[A-Za-z]*(R|D)[A-Za-z]*(\s|=).*""",
       tunnel = CASE(raw RLIKE """.*\s-[A-Za-z]*D[A-Za-z]*(\s|=).*""", "socks_dynamic",
                     raw RLIKE """.*\s-[A-Za-z]*R[A-Za-z]*(\s|=).*""", "reverse",
                     "unknown"),
// A key outside the key store is the loader shape, not an administrator habit.
       key_outside_store = cmd LIKE "*-i *" AND NOT cmd LIKE "*/.ssh/*" AND NOT cmd LIKE """*\\.ssh\\*""",
// -N (no command), -f (background) and autossh all mean "keep this open", which a session does not.
       quiet = cmd LIKE "*-n *" OR cmd LIKE "*-f *" OR cmd LIKE "*autossh*",
       proxy_cmd = cmd LIKE "*proxycommand*"
// Path-suffix test, so a bundled or renamed copy under an application folder still matches.
| WHERE (exe LIKE "*/ssh.exe" OR exe LIKE "*/plink.exe" OR exe LIKE "*/ssh" OR exe LIKE "*/plink")
  AND flag
// Destination: user@host when present, else the last token - which keeps aliases instead of dropping them.
| GROK process.command_line """%{USERNAME:ssh_user}@(?<dest_at>[A-Za-z0-9.-]+)"""
| EVAL dest = TO_LOWER(COALESCE(dest_at, last_token)),
       dest_class = CASE(dest RLIKE """[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}""", "ipv4",
                         dest RLIKE """.*:[0-9a-f]{1,4}:.*""", "ipv6",
                         dest LIKE "*.*", "fqdn",
                         "alias")
// Sanctioned destinations and the devbox platform, as command-line scoped exclusions.
| WHERE NOT (dest LIKE "*.corp.example" OR dest LIKE "*.ad.example" OR cmd LIKE "*devbox*")
// Private and special ranges, IPv4 only. 100.64.0.0/10 is CGNAT - Tailscale lives there, and a devbox on a
// tailnet otherwise reads as an external destination.
  AND NOT CASE(dest_class == "ipv4",
               CIDR_MATCH(dest, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                          "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8"), false)
// One row per host, user, destination and tunnel type: the retry loop becomes a count, not a flood.
| STATS launches = COUNT(*),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        key_outside = COUNT(*) WHERE key_outside_store,
        quiet_launches = COUNT(*) WHERE quiet,
        proxy_chains = COUNT(*) WHERE proxy_cmd,
        samples = MV_SLICE(VALUES(process.command_line), 0, 3),
        parents = MV_SLICE(VALUES(process.parent.executable), 0, 2)
    BY host.name, user.name, dest, dest_class, tunnel
// Fleet rarity: a destination only this host tunnels to is the interesting one. A sanctioned platform is
// tunnelled to from many hosts, and drops out of the alert path without a list.
| INLINE STATS dest_hosts = COUNT_DISTINCT(host.name) BY dest
// The alert conditions: an alias with no visible destination still matters when the launch is quiet or the
// key came from outside the store; a named destination matters when one host invented the relationship.
// 2 hosts / 3 launches are starting values - the baseline at the foot of this file is the source for both,
// and the 30-day list it prints is the entity-pair list to review before turning notifications on.
| WHERE key_outside >= 1 OR proxy_chains >= 1
     OR (dest_hosts <= 2 AND (quiet_launches >= 1 OR launches >= 3))
| SORT launches DESC
| LIMIT 100
```

Deploy every 5 minutes over the last 15. Suppress by `host.name` + `dest` for 24h.

## Reading the alert
- **`key_outside`** is the strongest column: a tunnel authenticated with `-i` outside `~/.ssh` is scripted, not typed.
- **`launches` and `quiet_launches`** together give the retry loop. Three or more launches of the same destination in a quarter hour was a person once, and has been a loop every time since.
- **`tunnel`** separates the two egress shapes: `socks_dynamic` turns the host into a proxy, `reverse` gives the outside world a path back in.
- **`parents`** is the attribution that matters on a workstation - `explorer.exe`/`bash` is a human, an editor extension host or `powershell.exe` is not.
- **`dest_class`** of `alias` means the destination lives in `~/.ssh/config`. Those rows survive now, and they are the ones to read the config file for.

## What it still misses
- **`DynamicForward` in the config with no flags on the command line** - the alias branch catches the launch but cannot see the forward, so it needs the config file, which is not in this feed.
- **Non-ssh tunnelling**: `chisel`, `ligolo`, `ngrok`, `socat`, `ncat`, `cloudflared`, and reverse tunnels built by a custom binary. The executable test is deliberately ssh/plink-only, because widening it to "any process that opens a long-lived external connection" is a different rule with a different noise profile.
- **Interactive sessions** (`ssh user@host`, `scp`, `sftp`, `-L` local forwards) - not matched by design; `-L` is a separate question about egress that deserves its own rule.
- **A tunnel over a permitted port** with the port set in the config, which is the `ssh.egress_port_evasion` case the original had in mind and still needs the config file to confirm.
- **Linux sensor coverage**, if the Falcon deployment is not uniform across the estate's servers.

## Baseline
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp >= NOW() - 30 days
  AND event.action == "processrollup2"
// leading-wildcard path-suffix tests on purpose: the executable can live in an application folder, and there
// is no indexed field for "this is ssh"
  AND (process.executable LIKE "*/ssh" OR process.executable LIKE "*/ssh.exe"
       OR process.executable LIKE "*/plink" OR process.executable LIKE "*/plink.exe")
| EVAL cmd = TO_LOWER(process.command_line), raw = process.command_line,
       flag = raw RLIKE """.*\s-[A-Za-z]*(R|D)[A-Za-z]*(\s|=).*"""
| WHERE flag
| GROK process.command_line "%{USERNAME:ssh_user}@(?<dest_at>[A-Za-z0-9.-]+)"
| EVAL dest = TO_LOWER(COALESCE(dest_at, MV_LAST(SPLIT(cmd, " "))))
| STATS launches = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY dest
| SORT hosts DESC
| LIMIT 40
```
Every destination in this list with a high `hosts` count is a sanctioned platform, and every one with `hosts` of 1-2 is what the rule alerts on. That is the list to review before enabling, and the entity pairs to record.

## References
- `rules/07-crowdstrike-fdr/CS25-editor-extension-ssh-backdoor.md` - the October 2026 Cursor extension loader, which is the `-i`-outside-the-store and editor-parent case from the other direction
- MITRE T1572 (protocol tunnelling), T1071 (application layer protocol), T1105-adjacent egress tooling
- `PORTS-REFERENCE.md` - SSH on 22 and the `-p`/`Port` evasion row
- Elastic ES|QL `GROK`, `MV_LAST`, `CIDR_MATCH` and `RLIKE` semantics in `docs/ESQL-CONVENTIONS.md`
