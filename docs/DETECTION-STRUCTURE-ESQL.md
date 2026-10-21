# Detection structure: ES|QL (Elastic)

Keep detections short. Most are one event, one precise match, and the fields someone needs to triage it. Write that first. Reach for counting, baselines and enrichment only when the question can't be answered from a single event, and then keep only the complexity it needs.

> **Golden rule: never do work on a row you are about to throw away.**

---

## 1. The default shape

```esql
FROM <index> METADATA _id, _index, _version
| WHERE event.action == "<event>" AND <cheap filters>
| GROK <content field> """(?i)(?<matched><precise pattern>)"""
| WHERE matched IS NOT NULL
| KEEP @timestamp, host.name, matched, <content field>, _id, _index, _version
```

CS19 is the example:
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action == "phpevalstring" AND data.event_platform == "Lin"
| GROK data.PhpEvalContent """(?i)(^|[^\w$>:])(?<matched>(system|shell_exec|exec|passthru|popen|proc_open|pcntl_exec)\s{0,16}\(.{1,64})"""
| WHERE matched IS NOT NULL
| KEEP @timestamp, event.action, host.name, matched, data.PhpEvalContent, _id, _index, _version
```

- **Filter on the event first,** with what the index answers: `==`, `IN`, `IS NULL`, ranges, `CIDR_MATCH`, prefix `LIKE "abc*"`. No function around a field here (`TO_LOWER`, `COALESCE`, casts): it makes every row run in memory. List case variants instead of lowercasing.
- **Put the precision in the pattern.** One tight regex that says exactly what the bad thing looks like beats a list of command lines and a pile of exclusions. Bound the gaps (`.{0,32}`, `\s{0,16}`) so it can't wander across a whole script.
- **`GROK` when `RLIKE` can't do it.** `RLIKE` is Lucene regex: no `\s`, `\b` or lookarounds, no case flag, and it must match the whole value. `GROK` takes a full regex (`(?i)`, `\s`, `\b`), matches anywhere in the value, and turns the named group into a column, so the alert shows exactly what matched. Use triple quotes so backslashes reach the regex as written. Don't name the group `match`: it collides with the `MATCH` function.
- **`RLIKE` or `LIKE` in the `WHERE`** is fine when the pattern is simple and whole-value. A leading wildcard needs a comment saying why nothing cheaper works.
- **Output** the time, the host, the match and the raw field, so the analyst sees the hit in context. A short `CASE` that turns a code into words (`"1"` to `"FILE WRITTEN"`) is fine. Non-aggregating rules keep `_id`, `_index` and `_version` for the alert.
- **Comments** say what a step does when it isn't obvious from the line itself. No stage labels.

---

## 2. When it has to count or compare

Some questions can't be answered from one event: a count over time (scanning, spraying), something seen for the first time, two events that must line up (a request denied, then issued). Then the query becomes a funnel, and the order matters for cost:

```
FROM → WHERE (index-answerable) → EVAL (only what STATS needs) → STATS BY <alert entity> → WHERE <threshold> → EVAL labels → KEEP
```

Keep the order in mind; don't label it in the query. B01 (scanning), CS17 (TruffleHog) and AD14 (ESC7) are this kind.

- **Reduce once,** `BY` the entity the alert is about, so one row is one potential alert. The key must never be null: a null key lumps unrelated events together. A second `STATS` needs a comment saying why.
- **Count conditionally** (`STATS x = COUNT(*) WHERE <cond>`) rather than building a flag column and summing it.
- **Cheap aggregates:** `COUNT`, `COUNT_DISTINCT`, `MIN`, `MAX`, `SUM`, conditional `... WHERE`. `VALUES()` on a high-cardinality field is not: bound it with `MV_SLICE` or `TOP`, or leave the detail to a pivot query.
- **`INLINE STATS`** only for population context that has to be known before the threshold, such as how many hosts do the same thing.
- **Thresholds** sit straight after the reduce, each with a comment saying where the number came from (section 4). Labels and lookups come after, on the few rows left.
- **Nulls:** `!=` and `NOT IN` drop null rows. Write `(f IS NULL OR f NOT IN (...))` when nulls must survive.

---

## 3. Design rules

1. **Check the telemetry before writing logic:** event names and their casing, which fields are filled on which events.
2. **Link events by stable IDs** (process, session, request ID), never by display names.
3. **One question per rule.** If the labels answer unrelated questions, split it.
4. **The rule schedule is the time window.** The lookback must cover the longest duration the logic measures.
5. **Always set suppression:** fields and a duration.
6. **Narrow exclusions:** an entity pair (a host and the process that does this by design), never a whole host, user or address.
7. **Time zones:** ES|QL dates are UTC. Convert explicitly when logic depends on local time.

---

## 4. Baseline before threshold

Never guess a threshold. Measure the metric over a normal period (count, median, p95, p99, max), exclude or note abnormal periods, and set the threshold just above the upper percentile. Watch for artefacts: a max equal to the bucket size is a cap, not a measurement. Record the source in a comment next to the threshold; until it's measured, the comment says it's a starting value.

```esql
<the query up to its STATS>
| STATS n = COUNT(), p50 = PERCENTILE(<metric>, 50), p95 = PERCENTILE(<metric>, 95),
        p99 = PERCENTILE(<metric>, 99), max = MAX(<metric>)
```

A detection with no threshold (section 1) has nothing to baseline: run it over 30 days instead and look at what fires.

---

## 5. What a rule file carries

Front-matter: `id`, `name`, `category`, `status`, `language`, `index`, `mitre`, `data_source`, `suppression`. No severity: scoring is done outside the library.

Then, in plain prose, no fixed headings required:
- what it catches and why that's precise, in a few lines;
- the query and its schedule. CrowdStrike rules carry both ES|QL and LogScale;
- before turning it on: the fields to confirm, the placeholders to fill, a baseline query for any threshold;
- what it misses;
- what to do when it fires, with a pivot query if the alert leaves out detail the analyst needs.

Reject the draft if (`tools/lint_detections.py` checks these):
- a function wraps a field in the first `WHERE`, or a leading-wildcard `LIKE`/`RLIKE` there has no comment;
- `VALUES()` on a high-cardinality field is unbounded;
- a threshold has no recorded source;
- a second `STATS` has no comment;
- `METADATA` is on an aggregating rule;
- an exclusion removes an entire host, user or address;
- there's no suppression.

---

## 6. ES|QL gotchas

- `LIKE` without a wildcard is an exact match. `LIKE` and `RLIKE` are case-sensitive.
- `RLIKE` is Lucene regex: no `\s`, `\b`, `\d` or lookarounds, and it must match the whole value. Use `GROK` for anything more.
- `GROK` returns null when the pattern doesn't match; filter on the named column after it.
- No bitwise operators: test bit n with `(x / 2^n) % 2 == 1`.
- Divide with a cast (`a / b::double`) to avoid integer division.
- A null `CASE` condition counts as false. `DATE_DIFF` and similar return null on null input.
- `COUNT(expr)` counts non-null values. `COUNT_DISTINCT` is approximate, though exact at low cardinality.
