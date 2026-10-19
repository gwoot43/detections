---
id: AI06
name: VS Code or an AI code editor looks up a domain few other installs reach (malicious extension calling home)
category: ai
status: todo
severity: medium
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1195.001, T1027.018, T1071.001]
data_source: CrowdStrike FDR DnsRequest (joined to ProcessRollup2 in the LogScale version)
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Extensions for VS Code and its AI forks (Cursor, Windsurf) run inside the editor with the developer's access to code, keys and tokens, and attackers publish malicious ones. GlassWorm hid its code in invisible Unicode characters (T1027.018), spread through extension marketplaces (T1195.001) and called home through blockchain and calendar services. Whatever an extension does, its network traffic comes from the editor's own processes. Those processes reach the same few domains on every developer's machine: the marketplace, updates, telemetry, GitHub and the AI assistants.

- **Anchor:** DNS lookups made by the editor's processes (`Code.exe`, `Cursor.exe`, `Windsurf.exe` and their helpers), extensions included.
- **Corroborating property:** the domain is new for this host's editor. Its first lookup in the 7-day lookback was in the last 2 hours.
- **Exclusion by rarity:** the editor looks up this domain on at most 3 hosts. Everything an editor does for everyone drops out with no list to keep, whatever the malicious one is called.

## Query
Run hourly with a 7-day lookback.
```esql
FROM logs-crowdstrike.fdr-*
// Anchor: lookups made by VS Code, Cursor or Windsurf, extensions included (they run inside the editor's processes).
// Names as Falcon reports them on Windows, macOS and Linux.
| WHERE event.action == "DnsRequest"
  AND (process.name IN ("Code.exe", "code", "Code - Insiders.exe", "code-tunnel.exe", "Cursor.exe", "cursor", "Windsurf.exe", "windsurf")
       OR process.name LIKE "Code Helper*" OR process.name LIKE "Cursor Helper*" OR process.name LIKE "Windsurf Helper*")
| EVAL dns.question.name = TO_LOWER(dns.question.name)
// Outside names only: single-label names (a host looking up itself or a neighbour), internal and reverse lookups,
// and your own domains (placeholder) say nothing about an extension calling home.
| WHERE dns.question.name LIKE "*.*" AND NOT dns.question.name RLIKE ".*\\.(local|internal|lan|arpa)\\.?"
  AND NOT dns.question.name LIKE "*<your_internal_domain>*"
// One row per host and domain: when this host's editor first looked it up in the 7 days.
| STATS first_seen = MIN(@timestamp), last_seen = MAX(@timestamp), lookups = COUNT(*), process.name = VALUES(process.name),
        process.entity_id = VALUES(process.entity_id), host.name = VALUES(host.name)
    BY host.id, dns.question.name
// Rarity: how many hosts' editors looked it up, counted before the newness check.
| INLINE STATS hosts = COUNT_DISTINCT(host.id) BY dns.question.name
// New for this host in the last 2 hours (two hourly runs), and reached by editors on at most 3 hosts.
| WHERE first_seen >= NOW() - 2 hours AND hosts <= 3
// One alert per host, listing every new rare domain.
| STATS first_seen = MIN(first_seen), last_seen = MAX(last_seen), lookups = SUM(lookups), dns.question.name = VALUES(dns.question.name),
        process.name = VALUES(process.name), process.entity_id = VALUES(process.entity_id), host.name = VALUES(host.name)
    BY host.id
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**, run over the last 7 days. DNS events don't carry the process name, so this version joins each lookup to its process:
```logscale
#event_simpleName=DnsRequest
// Outside names only: single-label names (a host looking up itself or a neighbour), internal and reverse lookups,
// your own domains (placeholder) and answers in private ranges say nothing about an extension calling home.
| DomainName=/\./ DomainName!=/\.(local|internal|lan|arpa)\.?$/i DomainName!=/<your_internal_domain>/i
| !cidr(FirstIP4Record, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10"])
// Anchor: lookups made by VS Code, Cursor or Windsurf, tied to the process by host and process ID. The join copies the
// process's path and command line onto each lookup; DNS events don't carry them.
| join({#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ ImageFileName=/[\\\/](code(-tunnel)?(\.exe)?|code - insiders\.exe|cursor(\.exe)?|windsurf(\.exe)?|(code|cursor|windsurf) helper[^\\\/]*)$/i},
       field=[aid, ContextProcessId], key=[aid, TargetProcessId],
       include=[ImageFileName, CommandLine, ParentBaseFileName], mode=inner)
| DomainName := lower(DomainName)
// One row per domain and host: when this host's editor first looked it up.
| groupBy([DomainName, aid], function=[min(@timestamp, as=first_seen), count(as=lookups),
                                       collect([ComputerName, ContextProcessId, ImageFileName, QueryStatus, FirstIP4Record])], limit=max)
// Rarity: one row per domain, counting the hosts whose editor looked it up. Alert when it's on at most 3 and new.
| groupBy([DomainName], function=[count(aid, distinct=true, as=hosts), sum(lookups, as=lookups),
                                  max(first_seen, as=newest_host_start),
                                  collect([aid, ComputerName, ContextProcessId, ImageFileName, QueryStatus, FirstIP4Record])], limit=max)
| _now := now()
| test(hosts <= 3 AND newest_host_start > _now - 7200000)
```

**Check before deploying:** the ES|QL version needs the process name on DNS events, which Falcon sends only on some sensor versions. Run `FROM logs-crowdstrike.fdr-* | WHERE event.action == "DnsRequest" | STATS named = COUNT(process.name), total = COUNT(*)` over an hour. If `named` is near zero, use the LogScale version, which joins each lookup to its process. In LogScale, `join` caps how many rows its inner query returns; raise its `limit` if your fleet starts more editor processes than that in 7 days.

## Suppression
Suppress by `host.id` for 24h. Alerts missing a key field are not suppressed. Aggregating rule: the 7-day lookback overlaps every run, and a host alerts once, when the new lookups start.

## Known false positives / exclusions
- A developer testing their own API from an extension (REST Client, Thunder Client), or a niche extension with its own backend that one person uses. It alerts once, then has a history.
- Set the threshold by how many people use these editors: `hosts <= 3` suits dozens of users. With a handful, use `hosts <= 1`.

## Triage
- Look at the domain: a blockchain RPC endpoint (Solana, Ethereum), a paste or calendar service used as a dead drop, or a domain registered days ago is the GlassWorm pattern.
- Find the extension: list the host's installed extensions (`~/.vscode/extensions`, `~/.cursor/extensions`) and their install dates; the one installed or updated just before `first_seen` is the suspect. Check it on the marketplace for removal notices.
- Rotate the developer's tokens (GitHub, npm, cloud), since that's what these extensions steal, and look for a hidden VNC or SOCKS proxy started from the editor (CS11, L14).

## Test
On a lab host with VS Code, install a test extension that fetches `https://<lab domain>/` on activation. The host should alert within the hour, naming the lab domain.
