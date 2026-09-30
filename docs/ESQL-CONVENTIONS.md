# ES|QL conventions used in this library

Reference for the recurring ES|QL patterns across the rule files. Rules link here instead of re-explaining.

## `METADATA _id, _index, _version`

```esql
FROM logs-windows.security-* METADATA _id, _index, _version
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

If you remove `METADATA` from a non-aggregating rule, the query still runs in Discover, but the rule loses clean alert-to-event linkage and deduplication.

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
5. **Put severity in the key when a rule can escalate.** A suppressed alert does not change severity when later events arrive. C11 keys on `severity` and I05 on a `landed` flag, so an escalation raises a new alert instead of folding into the old one.
6. **Do not suppress alerts with missing fields.** Otherwise an event missing the key folds into another alert, and attackers can influence which fields are present.
7. **Read the suppressed count.** A second action by the same attacker on the same entity inside the window folds into the open alert. A count that keeps climbing is a signal in its own right.

Alert suppression for ES|QL rules is available in current Elastic releases. Confirm your version supports it before relying on it.
