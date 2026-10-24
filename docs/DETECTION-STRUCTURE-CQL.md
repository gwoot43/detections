# Detection structure: CQL (CrowdStrike Falcon / LogScale)

Keep detections short. Most are one event, one precise match, and the fields someone needs to triage it. Write that first. Reach for grouping, baselines and lookups only when the question can't be answered from a single event, and then keep only the complexity it needs.

> **Golden rule: never do work on an event you are about to throw away.**

---

## 1. The default shape

```logscale
#event_simpleName=<Event> event_platform=<Lin|Win> <Field>=/(?<Match><precise pattern>)/iF
| select([@timestamp, ComputerName, Match, <Field>])
```

CS19 is the example:
```logscale
#event_simpleName=PhpEvalString event_platform=Lin PhpEvalContent=/(^|[^\w$>:])(?<Match>(system|shell_exec|exec|passthru|popen|proc_open|pcntl_exec)\s{0,16}\(.{1,64})/iF
| select([@timestamp, ComputerName, Match, PhpEvalContent])
```
```logscale
#event_simpleName=/^(ScriptControlScanInfo|ScriptControlDetectInfo)$/ event_platform=Lin ScriptContent=/(^|[^\w$>:])(?<Match>(system|shell_exec|exec|passthru|popen|proc_open|eval|assert)\s{0,16}\(.{0,32}\$_(GET|POST|REQUEST|COOKIE).{0,64})/iF
| case {
   ScriptContentSource=1 | ScriptContentSource := "FILE WRITTEN";
   ScriptContentSource=2 | ScriptContentSource := "SCRIPT EXECUTED";
   * ;
}
| select([@timestamp, #event_simpleName, ComputerName, ScriptContentSource, ScriptContentName, Match, ScriptContent])
```

- **Start with the tag** (`#event_simpleName`, other `#` fields): it decides which data is read at all. Several event types go in one anchored regex, `/^(EventA|EventB)$/`.
- **One regex filters and captures.** The named group (`?<Match>`) becomes a field, so the alert shows exactly what matched. `/i` instead of lowercasing; `F` runs it on LogScale's newer regex engine.
- **Put the precision in the pattern.** One tight regex that says exactly what the bad thing looks like beats a list of command lines and a pile of exclusions. Bound the gaps (`.{0,32}`, `\s{0,16}`) so it can't wander across a whole script.
- **Regex is unanchored.** That's what you want inside content; anchor (`^...$`) when you mean a whole value, like a file name or an event name.
- **Output with `select()`.** `table()` and `sort()` cap the rows unless you give them a limit. A short `case` that turns a code into words is fine; give it a `*` branch so events that match no branch aren't dropped.
- **Comments** say what a step does when it isn't obvious from the line itself. No stage labels.

---

## 2. When it has to count or compare

Some questions can't be answered from one event: a count over time (scanning, spraying), something seen for the first time, two event types tied together by a process ID. Then the query becomes a funnel, and the order matters for cost:

```
tags → cheap filters → := (only what groupBy needs) → groupBy(<alert entity>, limit=max) → threshold → case / match() → select()
```

Keep the order in mind; don't label it in the query. B01 (scanning), CS17 (TruffleHog), CP04 (RFM) and CS20 (PHP doing something new) are this kind.

- **Filter before any `:=` or function call.** Cheapest first: `field=value`, `in()`, `cidr()`, numeric comparisons, wildcards, then regex.
- **Group once,** on the entity the alert is about, with `limit=` set: `groupBy` truncates silently at its default. The key must never be missing. A second `groupBy` needs a comment saying why.
- **Cheap aggregates:** `count()`, `count(field, distinct=true)`, `min()`, `max()`, `sum()`. `collect()` on a high-cardinality field is not: count it, or leave the detail to a pivot query.
- **Tie event types together by ID** in one query (`defineTable` plus `match()` on `aid` and a process ID), not `join()`. A `join()` needs a comment saying why.
- **Thresholds** sit straight after the `groupBy`, each with a comment saying where the number came from (section 4). Compare against literals directly; `test()` for field-to-field or arithmetic.
- **Lookups and exclusions** (`match(file="aid_master_main.csv")`, host + process pairs) go after the threshold, on the few rows left.
- **A `case` used as a filter** has no `*` branch on purpose. Say so in a comment on the line above (`// Deliberately no * branch`).
- **Missing fields:** `test()` and arithmetic fail on a missing field. `default()` first.
- **`AND` and `OR` don't work inside `test()`, or next to any function call.** For AND, pipe the conditions: `| test(a) | test(b)`. For OR, use a `case` whose branches are the alternatives, with the "deliberately no `*` branch" comment: `| case { test(a); test(b); }`. A branch can pipe several conditions (`test(a) | test(b) | label := "x";`): it only matches if the event passes all of them, otherwise the next branch is tried. Plain field filters (`RemotePort=88 OR RemotePort=389`) can still use `AND` and `OR`.

---

## 3. Design rules

1. **Check the telemetry before writing logic:** `#event_simpleName` values, which fields are filled on which events, platform differences (`event_platform`).
2. **Link events by stable IDs, never names.** `aid` is the host; processes link through `TargetProcessId` on the process event and `ContextProcessId` or `ParentProcessId` on related events.
3. **One question per rule.** If the labels answer unrelated questions, split it.
4. **The schedule is the time window.** The search window must cover the longest duration the logic measures.
5. **Always set throttling:** fields and a duration.
6. **Narrow exclusions:** an entity pair (a host and the process that does this by design), never a whole host or user.
7. **Time zones:** `@timestamp` is epoch milliseconds in UTC. Pass `timezone=` when logic depends on local time.

---

## 4. Baseline before threshold

Never guess a threshold. Measure the metric over a normal period (count, median, p95, p99, max), exclude or note abnormal periods, and set the threshold just above the upper percentile. Watch for artefacts: a max equal to the bucket size is a cap, not a measurement. Record the source in a comment next to the threshold; until it's measured, the comment says it's a starting value.

```logscale
<the query up to its groupBy>
| groupBy([<dimension>], function=[count(), percentile(field=<metric>, percentiles=[50, 95, 99]), max(<metric>)], limit=max)
```

A detection with no threshold (section 1) has nothing to baseline: run it over 30 days instead and look at what fires.

---

## 5. What a rule file carries

The same as for ES|QL (`DETECTION-STRUCTURE-ESQL.md`, section 5): front-matter with no severity, then in plain prose what it catches, the query in both languages with its schedule, what to check before turning it on, what it misses, and what to do when it fires.

Reject the draft if (`tools/lint_detections.py` checks these):
- the query doesn't start with a tag field;
- an assignment runs before the filters;
- a `groupBy` has no explicit `limit`;
- a `case` has no `*` branch and no comment saying it's a deliberate filter;
- `table()`, or `sort()` without a limit, is the output;
- `collect()` is on a high-cardinality field;
- `join()` has no comment;
- `AND` or `OR` sits inside `test()` or beside a function call;
- a threshold has no recorded source;
- there's no throttling.

---

## 6. CQL gotchas

- Field names and values are case-sensitive.
- Regex is unanchored and matches substrings.
- A `case {}` without a `*` branch silently drops events that match no branch.
- `groupBy`, `collect()`, `table()`, `sort()` and `head()` all have default limits.
- `count()` counts events; `count(field)` counts events where the field exists.
- `:=` overwrites an existing field without warning. That's fine at the output (turning a code into words); use a new name anywhere a later step still needs the original.
- No bitwise `&` in filters: `bitfield:extractFlags()` tests bits.
- Time differences are in milliseconds.
