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
| EVAL sysprep_context = CASE(last_sysprep IS NOT NULL AND @timestamp - last_sysprep < 1 hour, "likely imaging", "no recent sysprep")
```
The same pattern works from Windows process creation (event 4688) if you audit process creation. It is also the pattern behind the correlation rules X01-X05.

## Enrich for context, do not silently suppress critical alerts

When a join is used to handle a false positive, prefer adding a context field over a hard `WHERE ... IS NULL` filter:

- Join keys such as `host.name` and process names are **attacker-influenceable**. A hard filter becomes a bypass if an attacker names a tool `sysprep.exe` or gets a host into your exclusion list.
- For low-volume critical rules, a tag like `"likely imaging"` lets the analyst close the alert in seconds without the rule going blind.

Reserve hard filters for sources you fully control, such as a sealed build network.
