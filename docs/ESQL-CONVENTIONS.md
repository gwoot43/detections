# ES|QL conventions used in this library

Reference for the recurring ES|QL patterns across the rule files. Rules link here instead of re-explaining.

## Index patterns

Every rule targets the data stream that Elastic's own integration writes to (`logs-<package>.<data_stream>-<namespace>`). If you ship a source another way, change the `FROM` line and the `index:` front-matter together.

| Source | Integration (data stream) | Pattern used |
|---|---|---|
| Windows Security channel | System (`security`); Windows (`forwarded`) for WEF collectors | `logs-system.security*, logs-windows.forwarded*` |
| Windows System channel | System (`system`) | `logs-system.system-*` |
| Defender AV Operational channel | Windows (`windows_defender`) | `logs-windows.windows_defender-*` |
| Defender for Endpoint alerts | M365 Defender (`alert`) | `logs-m365_defender.alert-*` |
| CrowdStrike FDR | CrowdStrike (`fdr`) | `logs-crowdstrike.fdr-*` |
| Entra sign-in and audit, Azure activity | Azure (`signinlogs`, `auditlogs`, `activitylogs`) | `logs-azure.<stream>-*` |
| O365 unified audit | O365 (`audit`) | `logs-o365.audit-*` |
| Zscaler ZIA web, firewall | Zscaler ZIA (`web`, `firewall`) | `logs-zscaler_zia.web-*`, `logs-zscaler_zia.firewall-*` |
| Imperva Cloud WAF | Imperva Cloud WAF (`event`) | `logs-imperva_cloud_waf.event-*` |
| F5 BIG-IP (incl. APM) | F5 BIG-IP (`log`) | `logs-f5_bigip.log-*`. APM is only parsed from Telemetry Streaming JSON, so see the N01-N04 prerequisites |

There is **no `windows.security` data stream**. Windows Security events land in `logs-system.security-*` when the Elastic Agent System integration collects them locally, or in `logs-windows.forwarded-*` when a collector reads the Forwarded Events channel. Elastic's prebuilt rules query both (`logs-system.security*, logs-windows.forwarded*, winlogbeat-*`). Add `winlogbeat-*` if any of your hosts still ship with Winlogbeat.

A wildcard pattern that matches no index is not an error in ES|QL, so listing both is safe. A concrete index name with no wildcard that does not exist fails the query.

Channels that the integrations do not collect by default (Partition/Diagnostic, DriverFrameworks-UserMode, Code Integrity) need a custom Windows event log input in the agent policy. The device rules in `rules/15-device/` list each one.

## `METADATA _id, _index, _version`

```esql
FROM logs-system.security*, logs-windows.forwarded* METADATA _id, _index, _version
```

`METADATA` exposes three document-level fields as columns you can use downstream:

| Field | What it is |
|---|---|
| `_id` | The unique ID of the source event document. |
| `_index` | The concrete backing index the document lives in. |
| `_version` | The document's version number. |

**It has no effect on detection logic.** It is plumbing for the Elastic Security detection engine:

- A **non-aggregating** rule (returns individual events, e.g. WE01) needs `_id` and `_index` so each alert points back to the exact source event, and so the engine deduplicates instead of re-alerting on the same document every run. `_version` supports that deduplication.
- An **aggregating** rule (built on `STATS`) omits it. A `STATS` output row is computed, not a source document, so there is no `_id` to reference. That is why the `STATS`-based rules in this library have no `METADATA` clause.

**Keep the metadata columns in the output.** A `KEEP` that doesn't list `_id, _version, _index` drops them from the result, and the rule loses deduplication just as if `METADATA` were missing: it re-alerts on the same document on every run while it's inside the lookback. Every non-aggregating rule here ends its `KEEP` with `_id, _version, _index`, as Elastic's prebuilt rules do.

If you remove `METADATA` from a non-aggregating rule, the query still runs in Discover, but the rule loses clean alert-to-event linkage and deduplication.

## CrowdStrike rules carry a LogScale version

Rules built on CrowdStrike FDR also include the same detection as a Falcon LogScale query (Advanced Event Search or Next-Gen SIEM), in a `logscale` block under the ES|QL one, so it can be run or scheduled in the Falcon console. It uses the raw Falcon field names (`#event_simpleName`, `ContextBaseFileName`, `RemoteAddressIP4`, `CommandLine`) rather than the ECS names the Elastic integration maps them to. Where ES|QL uses a feature LogScale lacks, such as `INLINE STATS`, the rule says how the LogScale version differs.

## Detection shape: anchor, corroborate, exclude

Don't build a rule from a long list of command-line variants. Each list misses the next variant and keeps growing. Build it from three parts:
1. **An anchor**: something every variant of the behaviour must do, such as an argument, a parent or a destination.
2. **One corroborating property** that makes it this tool or this risk: a flag it needs, its name, its signer or where it runs from. Any one of them is enough.
3. **A precise exclusion** for the known benign case, written as one clause rather than a list.

The model is Elastic's prebuilt rule for VS Code tunnels:
```eql
process where host.os.type == "windows" and event.type == "start" and
  process.args : "tunnel" and
  (process.args : "--accept-server-license-terms" or
   process.name : "code*.exe" or
   ?process.code_signature.subject_name : "Microsoft Corporation" or
   process.executable : ("?:\\ProgramData\\*", "?:\\Users\\Public\\*", "?:\\windows\\debug\\*",
                         "\\Device\\HarddiskVolume*\\Users\\Public\\*", "\\Device\\HarddiskVolume*\\ProgramData\\*",  "\\Device\\HarddiskVolume*\\windows\\debug\\*")) and
  not (process.name == "code-tunnel.exe" and process.args == "status" and process.parent.name == "Code.exe")
```

CS13 is the same rule on FDR. The translation:

| EQL | ES\|QL on FDR | LogScale |
|---|---|---|
| `process.args : "tunnel"` | `cmd RLIKE ".* tunnel( .*)?"`. ES\|QL comparisons return null on multivalue fields, so test the word in the command line | `CommandLine=/ tunnel( \|$)/i` |
| `process.name : "code*.exe"` | `pname LIKE "code*"` | `FileName=/^code/i` |
| `process.executable : (...)` | `exe LIKE """*\\programdata\\*"""`. FDR paths start `\Device\HarddiskVolumeN\`, so match from the folder down | `ImageFileName=/\\programdata\\/i` |
| `code_signature.subject_name` | Not in FDR process events. CS13 uses `--cli-data-dir` instead, which the persistent service always passes, and says what's left in its blind spot | `CommandLine=/--cli-data-dir/i` |
| `a or b or c` | `(a OR b OR c)` | A `case {}` with filter-only branches: an event passes if any branch matches |
| `not (...)` | `AND NOT (...)` | `NOT (... AND ...)` |

## No subqueries: use LOOKUP JOIN or ENRICH

ES|QL has **no SQL-style subqueries**. There is no `WHERE host.name IN (SELECT ...)`. Cross-dataset correlation uses one of two commands, both of which join on a **key, not a time window**.

### LOOKUP JOIN
```esql
| LOOKUP JOIN imaging_hosts ON host.name
```
- Joins rows from another index into the stream on a shared field.
- The right-hand index must be created in **`lookup` index mode**.
- GA in Elastic 9.x; tech preview in late 8.x. Confirm your version.
- Data is live: whatever is in the lookup index at query time is used.

### ENRICH
```esql
| ENRICH imaging_policy ON host.name WITH build_state
```
- Uses an **enrich policy** you create and execute ahead of time over a source index.
- Available on older versions where LOOKUP JOIN is not.
- The policy is a **point-in-time snapshot**. It only reflects changes when re-executed, so schedule re-execution.

### Which to use
Prefer LOOKUP JOIN when your version supports it: no policy to manage and no staleness. Use ENRICH on older clusters.

## Time-windowed correlation: materialise with a transform

Neither command answers "did X happen within N minutes of Y." For that, pre-compute the right-hand side with an **Elastic transform** writing to a lookup-mode index, then join on the key and compare timestamps in `EVAL`.

Example: "did sysprep run on this host shortly before the log was cleared" (WE01).

Transform source, scheduled every 10 minutes over the last hour:
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action == "ProcessRollup2" AND TO_LOWER(process.name) == "sysprep.exe"
| STATS last_sysprep = MAX(@timestamp) BY host.name
```
Write the output to `recent_sysprep` (lookup mode), then in the rule:
```esql
| LOOKUP JOIN recent_sysprep ON host.name
| EVAL sysprep_context = CASE(last_sysprep IS NOT NULL AND DATE_DIFF("minute", last_sysprep, @timestamp) >= 0 AND DATE_DIFF("minute", last_sysprep, @timestamp) <= 60, "likely imaging", "no recent sysprep")
```
The same pattern works from Windows process creation (event 4688) if you audit process creation. It is also the pattern behind the correlation rules X01-X05.

## Enrich for context, do not silently suppress critical alerts

When a join is used to handle a false positive, prefer adding a context field over a hard `WHERE ... IS NULL` filter:

- Join keys such as `host.name` and process names are **attacker-influenceable**. A hard filter becomes a bypass if an attacker names a tool `sysprep.exe` or gets a host into your exclusion list.
- For low-volume critical rules, a tag like `"likely imaging"` lets the analyst close the alert in seconds without the rule going blind.

Reserve hard filters for sources you fully control, such as a sealed build network.

## Alert suppression

Every rule file records its suppression in front-matter and in a Suppression section:

```yaml
suppression:
  fields: [host.name, user.name]   # up to 3 fields; must be columns in the query output
  duration: 1h                      # suppress per time period
  missing_fields: do_not_suppress   # alerts missing a key field are raised individually
```

`suppression: none` means the rule should page on every match.

### Suppression is not tuning
- **Exceptions** drop events you know are benign. They are how a rule becomes high fidelity.
- **Suppression** groups repeat alerts for the same entity into one alert with a count. It controls volume after the exceptions are right, never instead of them.

### Rules this library follows
1. **Suppress bursts, not distinct actions.** One attack that writes many identical events (shares, beacons, token refreshes, retries) is suppressed. One-shot, high-impact changes (federation, privileged groups, trusts, SID History) are not, because each event is a separate attacker action.
2. **Key on the triage entity.** Host, user, source IP or target object. A key that changes per event suppresses nothing; a key that is too broad merges separate incidents.
3. **Key fields must be output columns.** ES|QL suppression can only use fields the query returns, so the key must appear in `KEEP` or in the `STATS ... BY` list. Renamed columns (`acct`, `usr`, `h`) are used as-is.
4. **Aggregating and correlation rules always need it.** `METADATA _id` deduplication only works for rules that return source events. A `STATS` or `LOOKUP JOIN` rule re-alerts on every run whose lookback overlaps the previous one, so suppress on its grouping key.
5. **Put severity in the key when a rule can escalate.** A suppressed alert does not change severity when later events arrive. C11 keys on `severity` and S13-S15 on a `landed` flag, so an escalation raises a new alert instead of folding into the old one.
6. **Do not suppress alerts with missing fields.** Otherwise an event missing the key folds into another alert, and attackers can influence which fields are present.
7. **Read the suppressed count.** A second action by the same attacker on the same entity inside the window folds into the open alert. A count that keeps climbing is a signal in its own right.

Alert suppression for ES|QL rules is available in current Elastic releases. Confirm your version supports it before relying on it.

## Backslashes in LIKE and RLIKE

ES|QL processes a backslash twice: once in the string literal, then again as the `LIKE` escape character. A pattern written as `"*\\temp\\*"` reaches `LIKE` as `*\temp\*`, where `\t` means a literal `t` and `\*` a literal asterisk, so it never matches a path.

Use triple-quoted strings for patterns that match Windows paths. Triple-quoted strings skip string escaping, so the pattern text reaches `LIKE` unchanged and `\\` matches one backslash:

```
| WHERE process.executable LIKE """*\\temp\\*"""         // matches ...\temp\...
| WHERE cmd LIKE """*\\\\*"""                                // matches a UNC prefix \\
```

The equivalent in a normal string is four backslashes per backslash in the data (`"*\\\\temp\\\\*"`), which is what Elastic's own rules use. A backslash before a quote in a normal string (`"\""`) is ordinary string escaping and needs no change.

`RLIKE` uses Lucene regular expressions. They match the whole string implicitly and have no `^` or `$` anchors, which are read as literal characters. Use `.*` at either end instead, and `\\.` in a normal string for a literal dot.
