---
id: CP07
name: Log source went silent - a feed or a domain controller that was sending, and has stopped
category: controlplane
status: todo
language: esql
index: logs-system.security*, logs-windows.forwarded*, logs-yourorg-crowdstrike-data-default*, logs-azure.signinlogs-*, logs-azure.auditlogs-*, logs-o365.audit-*, logs-zscaler_zia.web-*, logs-windows.powershell_operational-*
mitre: [T1562.008, T1562.002]
data_source: every feed the catalogue depends on (meta-detection)
suppression:
  fields: [feed]
  duration: 6h
  missing_fields: do_not_suppress
---

Every other rule in the library is quiet when it has nothing to read. A domain controller whose forwarder died, an
FDR pipeline that stalled, or an expired O365 audit subscription looks exactly like a quiet day. This rule watches
the watchers. **It is the one meta-detection worth shipping before any of the others.**

ES|QL cannot emit a row for something that did not happen. So the rule asks the question it can answer: **which
sources sent data earlier in the window, and nothing recently?** A source that was alive six hours ago and silent for
the last hour is a feed that broke during the window.

Two queries, at two grains:

1. **Feed-level.** A whole data stream has stopped, such as all of FDR or all of the Entra sign-in logs.
2. **Host-level, for the hosts that matter.** One domain controller's Security log has stopped while the others carry
   on. A whole-feed check never sees that.

Falcon sensors have their own heartbeat rules: `CS05` (sensor stopped or stopped reporting) and `CP04` (Reduced
Functionality Mode). This rule does not repeat them.

## Query 1 — a feed stopped

Run every 30 minutes with a 6-hour lookback.

```esql
FROM logs-system.security*, logs-windows.forwarded*, logs-yourorg-crowdstrike-data-default*, logs-azure.signinlogs-*,
     logs-azure.auditlogs-*, logs-o365.audit-*, logs-zscaler_zia.web-*, logs-windows.powershell_operational-*
| WHERE @timestamp >= NOW() - 6 hours
| EVAL feed = COALESCE(data_stream.dataset, event.dataset, "unlabelled")
| STATS last_event = MAX(@timestamp), events_6h = COUNT(*) BY feed
| EVAL silent_minutes = DATE_DIFF("minute", last_event, NOW())
// source: each feed's delivery lag. 60 minutes sits above the normal batch delay of the O365 and Entra pipelines
// (typically 15 to 45 minutes); FDR and Windows forwarding are near-real-time and could alert at 20. Set per feed.
| WHERE silent_minutes >= 60
| SORT silent_minutes DESC
```

## Query 2 — a domain controller stopped

Run every 15 minutes with a 6-hour lookback.

```esql
FROM logs-system.security*, logs-windows.forwarded*
| WHERE @timestamp >= NOW() - 6 hours
| EVAL host_key = TO_LOWER(MV_FIRST(SPLIT(winlog.computer_name, ".")))
| WHERE host_key LIKE "dc*" OR host_key LIKE "*-dc*"     // your DC naming
| STATS last_event = MAX(@timestamp), events_6h = COUNT(*) BY host_key
| EVAL silent_minutes = DATE_DIFF("minute", last_event, NOW())
// source: a domain controller writes Security events every few seconds (Kerberos, logons); 30 silent minutes is
// a stopped forwarder or a stopped audit policy, not a quiet period
| WHERE silent_minutes >= 30
| SORT silent_minutes DESC
```

Repeat Query 2 for any other host class whose silence would blind a rule: Entra Connect servers, the CA, the DNS
servers `CS28` reads, and the F5 and Imperva feeds.

## Before turning it on

- **Confirm each feed's label.** Run Query 1 without the threshold and check that every feed you expect appears as
  its own `feed` row. FDR from your own pipeline may carry a different `data_stream.dataset`, or none at all, in which
  case it groups under `unlabelled`.
- **Learn each feed's normal lag** from `silent_minutes` across a normal week, and give slow feeds their own threshold.

## What it misses

- **A source that has been silent for the whole window.** If a DC stopped seven hours ago, it is absent from the six
  hours and produces no row. Keep the lookback well beyond the alert threshold (here six times longer). The complete
  fix is a lookup-mode index listing the hosts and feeds you **expect**, with `LOOKUP JOIN` turning "absent" into a
  row. Build that once your DC and feed list is stable.
- **A feed that keeps sending but stops sending the events that matter.** For example, a DC that still forwards
  System events while an audit-policy change (`WE02`) stopped `4769`. Per-event-code checks for your critical codes
  close that gap.
- **Volume drops** that are not full silence. A feed falling to 5% of normal still sends. A ratio against the same
  hour last week is the next step.

## When it fires

Before treating it as an attack, check the pipeline: the forwarder service, the integration's health page and the
ingest node. But read `WE01` (log cleared), `WE02` (audit policy) and `CS05` (sensor stopped) for the same host
first, because a deliberate silence is preceded by one of them.
