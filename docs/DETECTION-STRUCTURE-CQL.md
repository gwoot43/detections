# Detection Structure Standard: CQL (CrowdStrike Falcon / LogScale)

Every detection is a funnel: **refine, gate, reduce**. Each stage leaves fewer events than the last, and expensive work only happens on events that survived the stage before.

> **Golden rule: never do work on an event you are about to throw away.**

---

## 1. Pipeline (mandatory order)

```
#repo=<repo> #event_simpleName=<Event>                // 0 SCOPE    tag fields first
| <field>=<value> | in(field=<f>, values=[...])        // 1 GATE     cheap filters
| <new> := <expression>                                // 2 SHAPE    only what aggregation needs
| groupBy([<entity>], function=[<aggregates>], limit=max)  // 3 REDUCE
| <metric> >= <n>                                      // 4 DECIDE   thresholds
| case { ... ; * | ... }                               // 5 ENRICH   survivors only
| select([<fields>])                                   // 6 OUTPUT
```

Stages may be skipped when unused, but never reordered. A non-aggregating detection is stages 0, 1 and 6 only.

---

## 2. Stage rules

### 0. Scope
- Start every query with tag fields (`#repo`, `#event_simpleName`, other `#` tags). Tags narrow which data is read at all, so they're the cheapest filter there is.
- Match several event types with one anchored regex on the tag, `#event_simpleName=/^(EventA|EventB)$/`, or with `in()`.
- Never start with free-text search.

### 1. Gate
Preferred, cheapest first:
- `field=value`, `field!=value`
- `in(field=..., values=[...])`
- `cidr(field, subnet=[...])`
- Numeric comparisons against literals
- Wildcard `field=abc*`

Use with care:
- Regex `field=/.../`. Anchor it (`^...$`), keep it simple, and use the `/i` flag rather than lowercasing.
- Unqualified free-text search. Avoid it.

Rules:
- Gate before any assignment (`:=`) or function call.
- Matching is case-sensitive. For case-insensitive matches, use regex with `/i` or a case-insensitive option on the function. Don't transform the field first.
- Handle missing fields deliberately. Use `field=*` to require existence, and check how negated filters treat events that lack the field.

### 2. Shape
- Only assign fields that a later stage uses.
- Use `coalesce()` to unify a key that lives in different fields across event types.
- For conditional counts, assign a field only when the condition holds, then `count(that_field)` or `sum()` it.
- No per-event `format()` or string building unless that exact value is grouped or counted.
- Use `default()` before arithmetic or `test()` on fields that may be missing.

### 3. Reduce
- `groupBy()` on the entity the alert is about. One output row is one potential alert.
- The grouping key must never be missing. Events missing the key are dropped or collapse unrelated activity together.
- Set `limit=` explicitly. `groupBy` has a default group limit and truncates results beyond it.
- Use one `groupBy`. A second one needs a comment justifying it.
- Cheap aggregates: `count()`, `count(field, distinct=true)`, `min()`, `max()`, `sum()`, `avg()`.
- Expensive aggregates: `collect()` on high-cardinality fields. Use distinct counts and leave the detail to the triage pivot query.
- Correlate event types by putting them in one query and grouping on a shared ID. Avoid `join()` in scheduled detections. If you must use one, justify it in a comment.

### 4. Decide
- Thresholds live here and nowhere else.
- Compare against literals directly (`metric>=50`). Use `test()` for field-to-field comparisons or arithmetic.
- Every threshold has a recorded source (see section 4).

### 5. Enrich
- Build labels and severity with `case {}` or `if()`.
- Every `case {}` needs a `*` default branch, or events that match no branch are dropped.
- Lookups (`match()`) and formatting go here, on survivors only. Apply entity-keyed exclusions here as well; it's far cheaper than per-event matching.

### 6. Output
- Use `select()` for alert output. `table()` and `sort()` apply a default row limit.
- Output the entity, the decision metrics, and the minimum triage context.
- Detail goes in a separate pivot query, not in the alert.

---

## 3. Design rules

1. **Verify telemetry before writing logic.** Confirm `#event_simpleName` values, which fields are populated on which events, and the platform differences (`event_platform`).
2. **Link events by stable IDs, never by names.** In Falcon data, `aid` identifies the host. Processes link through `TargetProcessId` (on the process event) and `ContextProcessId` or `ParentProcessId` (on related events).
3. **Behaviour over static indicators.** File names, hashes and paths are fallbacks. Behaviour-backed hits rank above indicator-only hits.
4. **Model the current state, not "ever happened in the window".** For stateful conditions, measure the current episode or window.
5. **The schedule is the time window.** Prefer search interval = window over in-query bucketing. The search window must be at least the longest duration the logic measures.
6. **Always define throttling or suppression**: a field and a duration.
7. **Narrow exclusions.** Exclude entity combinations, not whole hosts or users. Keep exclusions centralised in lookup files, not hardcoded per rule.
8. **One question per rule.** If the labels answer unrelated questions, split the rule.
9. **Document blind spots**: what the telemetry or the logic cannot see.
10. **Be explicit about time zones.** `@timestamp` is epoch milliseconds in UTC. Pass `timezone=` to time functions when logic depends on local time or day boundaries.

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
```
#event_simpleName=/<pattern>/i
| groupBy([#event_simpleName, event_platform], function=[count(), count(aid, distinct=true, as=hosts)])
| sort(_count, order=desc)
```
```
#event_simpleName=<Event>
| head(10)
```

**Baseline:**
```
<detection stages 0-3>
| groupBy([<dimension>], function=[count(), percentile(field=<metric>, percentiles=[50, 95, 99]), max(<metric>)])
```

**Tuning:** run stages 0 to 3, then `sort(<metric>, order=desc, limit=50)` with no threshold.

**Triage pivot:** a non-aggregating query keyed on the alert entity (for example `aid` plus a process ID) that returns the detail the rule leaves out.

---

## 6. CQL gotchas

- Field names and values are case-sensitive.
- Regex is unanchored and matches substrings. Anchor with `^...$` when you mean a whole value.
- A `case {}` without a `*` branch silently drops non-matching events.
- `groupBy`, `collect()`, `table()`, `sort()` and `head()` all have default limits. Set the limit explicitly when completeness matters.
- `test()` and arithmetic on a missing field fail for that event. Set a fallback with `default()` first.
- `count()` counts events. `count(field)` counts events where the field exists.
- `:=` overwrites existing fields without warning. Use new names for derived fields.
- There's no bitwise `&` in filters. Use `bitfield:extractFlags()` to test individual bits.
- Time differences are in milliseconds. Convert explicitly, for example divide by 60000 for minutes.
- `join()` is bounded and expensive. Results beyond its limit are silently incomplete.

---

## 7. Agent output contract

Every detection must include:
1. **Query** following stages 0 to 6, with a short comment per stage.
2. **Rule settings**: schedule, search window, throttle field and duration, severity.
3. **Telemetry assumptions**: the event names and fields relied on, and the discovery query that confirms them.
4. **Baseline query and threshold source** for every threshold.
5. **Blind spots.**
6. **Triage pivot query.**

Reject the draft if:
- The query does not start with tag fields.
- An assignment or function runs before the gate filters.
- `collect()` is used on a high-cardinality field.
- A `groupBy` has no explicit `limit`.
- A `case {}` has no `*` branch.
- A threshold has no source.
- The search window is shorter than the logic's longest duration.
- An exclusion removes an entire host or user.
- The grouping key can be missing.
- Events are linked by name instead of an ID.
- `join()` is used without justification.
