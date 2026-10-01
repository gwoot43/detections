# Behaviour-based detections

These rules trigger on what a tool does, not what it is called. Each one counts a behaviour (fan-out, cadence, volume) over a time window using ES|QL aggregation, so renaming or recompiling a tool does not evade them. They complement the string- and signature-based rules elsewhere in the library, which stay useful for named, unmodified tooling.

Design constraints for this folder:
- **No lookups or custom indexes.** All exclusions are written inline in the query (by host name, process name or account), since there are no enrichment indexes.
- **Thresholds are starting points.** Every count was chosen to sit above normal activity in a typical estate. Tune each on two weeks of your own data before enabling.
- **Aggregating rules re-alert.** They carry suppression keyed on the triage entity so overlapping lookbacks do not page twice. See ../../docs/ESQL-CONVENTIONS.md.

| Rule | Behaviour | Tools it catches by behaviour |
|---|---|---|
| B01 | One host connects to many hosts | nmap, masscan, rustscan, custom scanners |
| B02 | One host sweeps many ports on one target | any port scanner |
| B03 | SMB/RPC/LDAP fan-out across the estate | BloodHound/SharpHound, ADExplorer, PingCastle, net loops |
| B04 | Fan-out on remote-admin ports | CrackMapExec/NetExec, Impacket, PsExec loops |
| B05 | One account authenticates to many hosts | pass-the-hash tooling, credential-spray lateral movement |
| B06 | Regular outbound callbacks to one destination | Cobalt Strike, Sliver, Mythic, Havoc beacons |
| B07 | One process reads very many files fast | TruffleHog, gitleaks, data collection, stealers |
| B08 | One process reads many credential stores | LaZagne, infostealers, secret scanners |
| B09 | Burst of distinct discovery commands | post-exploitation orientation, loaders |
