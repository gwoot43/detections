# Behaviour-based detections

These rules trigger on what a tool does, not what it is called. Each one counts a behaviour (fan-out, cadence, volume) over a time window using ES|QL aggregation, so renaming or recompiling a tool does not evade them. They complement the string- and signature-based rules elsewhere in the library, which stay useful for named, unmodified tooling.

**Activity first, filename fallback.** Where a behaviour belongs to a known tool family, the rule also alerts when one of those tools starts by name, even below the threshold or when the telemetry the behaviour needs is missing (raw-packet scans, file-read events switched off). The two are grouped on the same host and process, so a named tool that also shows the behaviour is one alert. A `finding` (or `label`) column says which fired. B01, B04, B07 and B08 here, and CS03, CS16 and CS17, work this way; tools that already have a by-name rule (W09 for AD tooling, W10 for tunnels on Windows) aren't repeated.

Design constraints for this folder:
- **Built to the detection standard** (`../../docs/DETECTION-STRUCTURE-ESQL.md`, `../../docs/DETECTION-STRUCTURE-CQL.md`). B01 is the worked example: numbered stages, settings, discovery and baseline queries, blind spots and a triage pivot query.
- **No lookups or custom indexes yet.** Exclusions are written inline in the query as placeholders, as entity pairs (a host and the process that does this by design), never a whole host. The standard wants them in one central lookup; this is where it would go.
- **Thresholds are starting points until baselined.** Every count was chosen to sit above normal activity in a typical estate, which is a guess. Measure each with the rule's baseline query (B01 shows how) on your own data, and record the result next to the threshold before enabling.
- **Aggregating rules re-alert.** They carry suppression keyed on the triage entity so overlapping lookbacks do not page twice. See ../../docs/ESQL-CONVENTIONS.md.
- **Key FDR rules on `host.id`.** It is the Falcon agent ID and is always present. `host.name` and `user.name` are only filled when the CrowdStrike integration's host and user metadata enrichment is on, so they are output columns, not grouping keys. `user.name` is reduced to the bare, lowercased account name before grouping.
- **FDR connection and file-open events often lack a process name.** It comes from `ContextBaseFileName`, which older sensors do not send. Rules read it as `unknown` (network) or group per process instance with `process.entity_id` (file reads), and name exclusions only apply when the name is present.

| Rule | Behaviour | Tools it catches by behaviour |
|---|---|---|
| B01 | One process scans: 10+ hosts on 10+ ports (mixed, critical), 20+ ports on at most 5 hosts (high), or 50+ hosts (medium); in Palo Alto, the same shapes counted on unanswered probes. Known scanner names in an optional separate query | Any scanner, script or implant scanning internally with connections; raw-packet scans and devices without Falcon through the firewall |
| B04 | Fan-out on remote-admin ports (SMB/RPC, WinRM, RDP), or LDAP fan-out to several domain controllers; falls back to CrackMapExec, NetExec or Impacket by name | CrackMapExec/NetExec, Impacket, PsExec loops, BloodHound/SharpHound, ADExplorer |
| B05 | One account authenticates to many hosts | pass-the-hash tooling, credential-spray lateral movement |
| B06 | Regular outbound callbacks to one destination | Cobalt Strike, Sliver, Mythic, Havoc beacons |
| B07 | One process reads very many files fast; falls back to gitleaks or Nosey Parker run on a folder | TruffleHog, gitleaks, data collection, stealers |
| B08 | One process reads many credential stores; falls back to LaZagne, HackBrowserData, SharpChrome or SharpDPAPI by name | LaZagne, infostealers, secret scanners |
| B09 | Burst of distinct discovery commands; high when it includes domain enumeration (`net group /domain`, `nltest /dclist`, `whoami /priv`, `setspn -q`) | post-exploitation orientation, loaders, operators enumerating the domain |
| B10 | Steady callbacks from one to three users to an uncategorised or newly registered domain (Zscaler) | HTTP(S) C2 on fresh domains, whatever the implant, including devices without Falcon |
