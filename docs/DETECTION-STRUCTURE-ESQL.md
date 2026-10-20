# Detection Structure Standard: ES|QL (Elastic)

Every detection is a funnel: **refine, gate, reduce**. Each stage leaves fewer rows than the last, and expensive work only happens on rows that survived the stage before.

> **Golden rule: never do work on a row you are about to throw away.**

---

## 1. Pipeline (mandatory order)

```esql
FROM <narrowest index>                         // 0 SCOPE
| WHERE <index-answerable filters>             // 1 GATE
| EVAL  <only what the aggregation needs>      // 2 SHAPE   (runs on every row: keep minimal)
| STATS <cheap aggregates> BY <alert entity>   // 3 REDUCE  (one STATS where possible)
| WHERE <thresholds>                           // 4 DECIDE
| EVAL  <labels, severity, trimming>           // 5 ENRICH  (survivors only)
| KEEP  <triage fields>                        // 6 OUTPUT
```

Stages may be skipped when unused, but never reordered. A non-aggregating detection is stages 0, 1 and 6 only.

---

## 2. Stage rules

### 0. Scope
- Use the narrowest index or data stream that holds the data.
- Only add `METADATA` fields when the rule is non-aggregating and needs them.

### 1. Gate (most important)
Allowed: filters Elasticsearch can answer from the index.
- `==`, `IN (...)`, `IS NULL`, `IS NOT NULL`
- Numeric and date ranges
- `CIDR_MATCH`
- Prefix `LIKE "abc*"`

Not allowed:
- Functions around a field (`TO_LOWER`, `COALESCE`, `CONCAT`, casts). These can't use the index, so every row is evaluated in memory.
- Leading-wildcard `LIKE` and `RLIKE`, unless nothing else works. If you use one, justify it in a comment.

Rules:
- Gate on event type or action first.
- Handle case variants by listing them, not with `TO_LOWER`.
- Handle nulls deliberately. `!=` and `NOT IN` drop null rows, so write `(f IS NULL OR f NOT IN (...))` when nulls must survive.

### 2. Shape
- Only create fields that a later stage uses.
- No per-row string building unless that exact value is grouped or counted.
- Prefer conditional aggregation (`STATS x = COUNT(*) WHERE <cond>`) over a flag column summed later.

### 3. Reduce
- Group `BY` the entity the alert is about. One row is one potential alert.
- The grouping key must never be null. A null key collapses unrelated events into one group.
- Use one STATS. A second STATS needs a comment justifying it.
- Cheap aggregates: `COUNT`, `COUNT_DISTINCT`, `MIN`, `MAX`, `SUM`, `AVG`, conditional `... WHERE`.
- Expensive aggregates: `VALUES()` on high-cardinality fields. Replace with `COUNT_DISTINCT` and leave the detail to the triage pivot query.
- `INLINE STATS` is only for population context that must be computed before the threshold, such as rarity across all entities.

### 4. Decide
- Thresholds live here and nowhere else.
- Every threshold has a recorded source (see section 4).

### 5. Enrich
- `finding` and `severity` labels and other `CASE` logic go here.
- Trim multivalue output with `MV_SLICE`.

### 6. Output
- `KEEP` the entity, the decision metrics, and the minimum triage context.
- Detail goes in a separate pivot query, not in the alert.

---

## 3. Design rules

1. **Verify telemetry before writing logic.** Confirm event names and their casing, which fields are populated on which events, and how events relate to each other.
2. **Link events by stable IDs** (process, session, connection, request ID), never by display names.
3. **Behaviour over static indicators.** Names, hashes and paths are fallbacks. Behaviour-backed hits rank above indicator-only hits.
4. **Model the current state, not "ever happened in the lookback".** For stateful conditions, measure the current episode or window.
5. **The rule schedule is the time window.** Prefer interval = window over in-query time bucketing. The lookback must be at least the longest duration the logic measures.
6. **Always define suppression**: a field and a duration.
7. **Narrow exclusions.** Exclude entity combinations, not whole assets or users. Keep exclusions centralised (a lookup index or list), not hardcoded per rule.
8. **One question per rule.** If the labels answer unrelated questions, split the rule.
9. **Document blind spots**: what the telemetry or the logic cannot see.
10. **Be explicit about time zones.** ES|QL dates are UTC, so convert explicitly when logic depends on local time or day boundaries.

---

## 4. Baseline before threshold

Never guess a threshold. For each threshold:
- Measure the distribution of the metric over a representative period of normal activity: count, median, upper percentiles and max.
- Exclude known abnormal periods (maintenance, incidents) or record that they are included.
- Split by a dimension only if it genuinely changes what "normal" looks like for this detection.
- Check what the baseline filters out, as well as what it keeps.
- Watch for artefacts. A max equal to a window or bucket size is a cap, not a measurement.

Default: set the threshold just above the upper percentile, plus a buffer for ingest lag. Use a lower percentile when the sample is small. Record the source in a comment next to the threshold.

---

## 5. Helper queries (templates)

**Discovery:**
```esql
FROM <index>
| WHERE <event field> LIKE "<prefix>*"
| STATS events = COUNT(), entities = COUNT_DISTINCT(<entity>) BY <event field>
| SORT events DESC
```
```esql
FROM <index>
| WHERE <event field> == "<event>"
| LIMIT 10
```

**Baseline:**
```esql
<detection stages 0-3>
| STATS n = COUNT(), p50 = PERCENTILE(<metric>, 50), p95 = PERCENTILE(<metric>, 95),
  p99 = PERCENTILE(<metric>, 99), max = MAX(<metric>) [BY <dimension>]
```

**Tuning:** run stages 0 to 3, then `SORT <metric> DESC | LIMIT 50` with no threshold.

**Triage pivot:** a non-aggregating query keyed on the alert entity that returns the detail the rule leaves out.

---

## 6. ES|QL gotchas

- `LIKE` without a wildcard is an exact match.
- `LIKE` and `RLIKE` are case-sensitive.
- `RLIKE` uses Lucene regex: no `\s`, `\b`, `\d` or lookarounds, and the pattern must match the whole value.
- There are no bitwise operators. Test bit n with `(x / 2^n) % 2 == 1`. Integer division truncates.
- Divide with a cast (`a / b::double`) to avoid integer division.
- A null `CASE` condition is treated as false.
- `COUNT(expr)` counts non-null values. `COUNT_DISTINCT` is approximate, though exact at low cardinality.
- After `STATS ... BY a, b`, rows are unique, so `COUNT(a)` replaces `COUNT_DISTINCT(a)` in a later `BY b`.
- Functions such as `DATE_DIFF` return null on null input. Guard before filtering on the result.
- `VALUES()` has no useful cap. Bound it with `MV_SLICE` or don't use it.

---

## 7. Agent output contract

Every detection must include:
1. **Query** following stages 0 to 6, with a short comment per stage.
2. **Rule settings**: interval, lookback, suppression field and duration, severity.
3. **Telemetry assumptions**: the events and fields relied on, and the discovery query that confirms them.
4. **Baseline query and threshold source** for every threshold.
5. **Blind spots.**
6. **Triage pivot query.**

Reject the draft if:
- A function wraps a field in the gate.
- `VALUES()` is used on a high-cardinality field.
- A threshold has no source.
- The lookback is shorter than the logic's longest duration.
- An exclusion removes an entire asset or user.
- The grouping key can be null.
- Events are linked by name instead of an ID.
