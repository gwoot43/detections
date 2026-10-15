# Behaviour-based detections

These rules trigger on what a tool does, not what it is called. Each one counts a behaviour (fan-out, cadence, volume) over a time window using ES|QL aggregation, so renaming or recompiling a tool does not evade them. They complement the string- and signature-based rules elsewhere in the library, which stay useful for named, unmodified tooling.

Design constraints for this folder:
- **No lookups or custom indexes.** All exclusions are written inline in the query (by host name, process name or account), since there are no enrichment indexes.
- **Thresholds are starting points.** Every count was chosen to sit above normal activity in a typical estate. Tune each on two weeks of your own data before enabling.
- **Aggregating rules re-alert.** They carry suppression keyed on the triage entity so overlapping lookbacks do not page twice. See ../../docs/ESQL-CONVENTIONS.md.
- **Key FDR rules on `host.id`.** It is the Falcon agent ID and is always present. `host.name` and `user.name` are only filled when the CrowdStrike integration's host and user metadata enrichment is on, so they are output columns, not grouping keys. `user.name` is reduced to the bare, lowercased account name before grouping.
- **FDR connection and file-open events often lack a process name.** It comes from `ContextBaseFileName`, which older sensors do not send. Rules read it as `unknown` (network) or group per process instance with `process.entity_id` (file reads), and name exclusions only apply when the name is present.

| Rule | Behaviour | Tools it catches by behaviour |
|---|---|---|
| B01 | One process probes many internal host:port endpoints (horizontal, vertical or mixed scan) | nmap, masscan, rustscan, custom scanners, when they open normal connections (raw-packet scans: CS12) |
| B04 | Fan-out on remote-admin ports (SMB/RPC, WinRM, RDP), or LDAP fan-out to several domain controllers | CrackMapExec/NetExec, Impacket, PsExec loops, BloodHound/SharpHound, ADExplorer |
| B05 | One account authenticates to many hosts | pass-the-hash tooling, credential-spray lateral movement |
| B06 | Regular outbound callbacks to one destination | Cobalt Strike, Sliver, Mythic, Havoc beacons |
| B07 | One process reads very many files fast | TruffleHog, gitleaks, data collection, stealers |
| B08 | One process reads many credential stores | LaZagne, infostealers, secret scanners |
| B09 | Burst of distinct discovery commands; high when it includes domain enumeration (`net group /domain`, `nltest /dclist`, `whoami /priv`, `setspn -q`) | post-exploitation orientation, loaders, operators enumerating the domain |
