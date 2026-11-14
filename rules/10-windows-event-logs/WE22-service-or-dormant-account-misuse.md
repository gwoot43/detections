---
id: WE22
name: Service account logging on interactively or over RDP, or a dormant account coming back to life
category: windows-event-logs
status: todo
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1078.002, T1078.003]
data_source: Windows Security 4624 (logon types 2, 10 and 11)
suppression:
  fields: [acct]
  duration: 24h
  missing_fields: do_not_suppress
---

Two questions about accounts being used in a way their owners never use them. They are one rule because the answer is
the same: credentials in the wrong hands.

1. **A service account logging on interactively or over RDP** (logon type 2, 10, or 11 for cached). Service accounts
   authenticate as services, batch jobs or network logons (types 3, 4 and 5). A human session for one means a person
   is typing with its password. **Alert grade.**
2. **A dormant account logging on again** after weeks of silence. Leavers whose accounts were never disabled, and
   long-forgotten test accounts, are the cheapest valid credentials an attacker can find. **Risk grade.** It needs a
   baseline window, which makes it the expensive half, so it runs once a day.

`I06` covers the related Tier-0 question: a privileged account logging on to a workstation.

## Query 1 — service account in a human session (alert)

Run every 15 minutes with a 20-minute lookback.

```esql
FROM logs-system.security*, logs-windows.forwarded* METADATA _id, _index, _version
| WHERE event.code == "4624"
  AND winlog.event_data.LogonType IN ("2", "10", "11")
| EVAL acct = TO_LOWER(COALESCE(winlog.event_data.TargetUserName, ""))
// your service-account naming convention (placeholders); leading wildcard on purpose, the suffix form is a convention
| WHERE acct LIKE "svc*" OR acct LIKE "sa-*" OR acct LIKE "*-svc" OR acct IN ("<named_service_account>")
| KEEP @timestamp, acct, winlog.event_data.TargetDomainName, winlog.event_data.LogonType, winlog.computer_name,
       source.ip, winlog.event_data.WorkstationName, winlog.event_data.LogonProcessName, _id, _version, _index
```

## Query 2 — dormant account returns (risk)

Run **once a day** over 30 days. The window is the cost. Restricting it to interactive and RDP logon types (2, 10
and 11) keeps the scan to a small slice of `4624`, because network logons (type 3) are most of the volume.

```esql
FROM logs-system.security*, logs-windows.forwarded*
| WHERE @timestamp >= NOW() - 30 days
  AND event.code == "4624"
  AND winlog.event_data.LogonType IN ("2", "10", "11")
| EVAL acct = TO_LOWER(COALESCE(winlog.event_data.TargetUserName, "")),
       recent = @timestamp >= NOW() - 24 hours
// computer accounts, and the window-manager and font-driver accounts Windows logs as type 2 on every boot
| WHERE acct != "" AND NOT ENDS_WITH(acct, "$") AND NOT (acct LIKE "dwm-*" OR acct LIKE "umfd-*")
| STATS logons_24h = COUNT(*) WHERE recent,
        logons_before = COUNT(*) WHERE NOT recent,
        previous_logon = MAX(CASE(NOT recent, @timestamp, NULL)),
        returned_at = MIN(CASE(recent, @timestamp, NULL)),
        hosts = MV_SLICE(VALUES(winlog.computer_name), 0, 5),
        sources = MV_SLICE(VALUES(TO_STRING(source.ip)), 0, 5)
    BY acct
// Baseline: an account active within the last 21 days is in use. A return after a longer gap, or a first
// interactive logon in 30 days, is the dormant case. Size the 21-day gap against your own leaver process and
// holiday patterns before enabling.
| WHERE logons_24h >= 1 AND (logons_before == 0 OR previous_logon < NOW() - 21 days)
| EVAL shape = CASE(logons_before == 0, "no_interactive_logon_in_30d", "returned_after_21d_gap"),
       days_silent = DATE_DIFF("day", previous_logon, returned_at)
| SORT returned_at DESC
| LIMIT 100
```

`no_interactive_logon_in_30d` mixes two populations: genuinely dormant accounts and brand-new starters. Join the
result to your HR joiners list, or check `whenCreated` in AD, before treating a new starter as dormant.

**A cheaper long-term version:** run an Elastic transform that keeps the last interactive logon per account in a
lookup-mode index, then `LOOKUP JOIN` today's logons against it. That replaces the 30-day scan with a one-day scan,
and it extends "dormant" to any length.

## Benign twins

- **Service accounts used by an admin at the console** during an incident or a migration. It is ticketable and
  rare, and the logon comes from a jump host.
- **Long leave** (parental, sabbatical), and contractors who return for a project.
- **Accounts used only quarterly**, such as audit or finance close accounts. They return on a calendar. Exclude them
  as account plus expected month.

## What it misses

- A service account used for **network** logons from an unexpected host (type 3). That is a source-address question,
  not a logon-type one. `WE13` and `B05` are closer.
- Dormant accounts used **only** in Entra or the VPN. `S09` (disabled and leaver accounts in Entra) and the F5 rules
  cover those surfaces.

## When it fires

For a service account in a human session: identify who was at `WorkstationName` / `source.ip`. Then rotate the
account's password and check its other logons since the last rotation. For a dormant account: disable it first, and
ask questions second.
