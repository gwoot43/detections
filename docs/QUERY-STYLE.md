# Query style

Every ES|QL query in this library is written to one shape, so an analyst can read any rule top to bottom in the same order: what it looks at, what it calls things, what it counts, what makes it fire, and what the alert shows. `ESQL-CONVENTIONS.md` covers the mechanics (index patterns, METADATA, suppression, escaping). This page covers layout.

## The reference query

```esql
FROM logs-zscaler_zia.web-*
| WHERE event.action == "allowed" AND destination.domain IS NOT NULL
  AND zscaler_zia.web.url.category.sub IN ("Miscellaneous or Unknown", "Newly Registered Domains")
| EVAL who = TO_LOWER(user.name), domain = TO_LOWER(destination.domain), slot = DATE_TRUNC(5 minutes, @timestamp)
| STATS requests = COUNT(*),
        active_slots = COUNT_DISTINCT(slot),
        first_seen = MIN(@timestamp),
        last_seen = MAX(@timestamp),
        paths = VALUES(url.path),
        user_agents = VALUES(user_agent.original),
        dest_ips = VALUES(destination.ip)
    BY who, domain
| EVAL span_hours = ROUND(DATE_DIFF("minute", first_seen, last_seen) / 60.0, 1),
       avg_per_slot = ROUND(TO_DOUBLE(requests) / active_slots, 1)
| WHERE active_slots >= 72 AND avg_per_slot >= 2
// prevalence: how many users pass the beacon checks for the same domain
| INLINE STATS beaconing_users = COUNT_DISTINCT(who) BY domain
| WHERE beaconing_users <= 3
| KEEP who, domain, requests, active_slots, span_hours, avg_per_slot, beaconing_users,
       first_seen, last_seen, paths, user_agents, dest_ips
```

It reads in one pass: allowed traffic to uncategorised domains, named `who`, `domain` and `slot`, counted per user and domain, turned into a rate, filtered by its thresholds in one line, narrowed to domains few users beacon to, then the columns the analyst needs.

## Order of stages

Use the stages you need, in this order:

| # | Stage | Holds |
|---|---|---|
| 1 | `FROM` | Index pattern. `METADATA _id, _index, _version` on rules that return events. |
| 2 | `WHERE` | Scope: event type, outcome, category. Raw fields, cheapest and most selective first, so Elasticsearch can filter in the index. |
| 3 | `EVAL` | Working names, defined once: lowercased or coalesced values, a time slot, a label. |
| 4 | `WHERE` | The detection logic and the exclusions, written against the working names. |
| 5 | `STATS` | One aggregation per line. `BY` the entity the alert is about. |
| 6 | `EVAL` | Values derived from the aggregates: rates, spans, ratios. |
| 7 | `WHERE` | Every threshold, together, as plain comparisons. |
| 8 | `INLINE STATS`, `WHERE` | Optional prevalence: how many entities pass for the same target, counted after the thresholds. |
| 9 | `KEEP` | Always last. What the alert shows, in triage order. |

A `WHERE` sits between `EVAL`s only when it filters on a value that a later `EVAL` or `STATS` needs to have filtered first (for example a `GROK` that should only run on matching events). Thresholds are not split across several `WHERE`s.

## Layout

- Each command starts a new line with `| `. Continuation lines indent two spaces and start with `AND` or `OR`.
- `STATS`: one aggregate per line, aligned under the first, with `BY` on its own line indented four spaces.
- `EVAL` with more than two assignments, or any long one: one assignment per line, aligned.
- A labelling `CASE` opens with `| EVAL label = CASE(`, then each condition on its own line indented four spaces with its label on the next line indented six (or on the same line when both are short), and `NULL)` last. `W04` is the worked example.
- Keep lines under about 120 characters. Wrap long `IN (...)` lists with the continuation aligned under the first value.
- Commands and functions in upper case (`VALUES`, `COUNT(*)`, `TO_LOWER`). Field names and working names in lower case.
- No `SORT` or `LIMIT` in a rule. The detection engine caps alerts per run, and a sort decides which rows get cut.

## Names

- Short, lower case, `snake_case`, and naming what the value is: `who`, `host`, `pname`, `parent`, `cmd`, `domain`, `slot`, `target`.
- Counts are plural nouns (`requests`, `failures`, `hosts`). Lists say what they hold (`user_agents`, `dest_ips`). Times are `first_seen` and `last_seen`.
- Never assign over a source field (`EVAL process.name = TO_LOWER(process.name)`). Give the transformed value its own name so a reader knows it is no longer the raw field.
- When a column is the source field unchanged, keep its ECS name (`host.id`, `user.name`, `source.ip`). Elastic Security links those to entity pages and risk scoring.

## Logic

- **One label per pattern.** When a rule matches several distinct patterns, write a `CASE` with one `condition, "label"` pair per line, then `WHERE label IS NOT NULL`, and keep the label in the output. The analyst sees which pattern fired.
- **Exclusions in one place,** as `WHERE NOT x IN (...)`. Wrap `x` in `COALESCE` if it can be empty, or the exclusion drops those rows too.
- Use `DATE_DIFF` for time spans and `TO_DOUBLE` for ratios, not casts to `long` or `::double`.

## Comments

At most one short line per stage, and only for what the query cannot say itself: why a threshold is where it is, or why an exclusion exists. Field-mapping caveats, false-positive reasoning and tuning advice belong in the rule's markdown sections, where they are easier to read and do not clutter the query.

## Output (`KEEP`)

- **Rules that return events:** `@timestamp`, the entity (`host.id`, `host.name`, `user.name`), the label or finding, the evidence, then `_id, _version, _index`.
- **Aggregating rules:** the `BY` keys, the values the thresholds test, `first_seen` and `last_seen`, then the context lists.
- Every suppression field must be one of these columns.
