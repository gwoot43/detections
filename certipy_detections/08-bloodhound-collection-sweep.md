---
id: SWEEP-01
name: BloodHound / SharpHound collection sweep - one account asks the DC for tickets to dozens of computers in minutes
language: esql
index: logs-yourorg-microsoft-windows*
mitre: [T1087.002, T1069.002, T1018, T1049]
data_source: Windows Security 4769 (DCs); optional 5140 (targets)
suppression:
  fields: [user.name]
  duration: 6h
  missing_fields: do_not_suppress
---
SharpHound's session, local-admin and group collection connects to every computer it can reach, and on a domain-joined host each connection first asks the DC for that computer's Kerberos service ticket. So **one account collecting tickets to dozens of different services inside a few minutes** is the sweep - a single event type, a single count, a single threshold.

What separates a collection run from a busy admin is **breadth in a short window**, not a name or a tool. A person opening sessions by hand reaches a handful of hosts in a quarter of an hour; SharpHound reaches them in seconds. So the measure is distinct service names per account over the rule's window, and the window is deliberately short enough that routine work cannot reach the threshold.

## Reading a 4769, field by field
- **`user.name`** (`TargetUserName`) is the account that **asked** for the ticket. When a machine asks, it arrives as `HOST$` or `HOST$@DOMAIN` - that `$` is the machine's own account name.
- **`winevt.event_data.service_name`** (`ServiceName`) is the **SPN that was requested**, e.g. `HOST/DC01`, `TERMSRV/FS01`, `MSSQLSvc/sql01:1433`, `krbtgt`. It is **not** an account name, so a ticket to a computer does **not** end in `$` - matching `*$` on this field matches almost nothing and the rule goes quietly blind.
- **`winevt.event_data.status`** is `0x0` on success. `0x20` (expired ticket, retried) is noise and is not an attack signal on its own.

The old version of this rule filtered `ENDS_WITH(service_name, "$")`. That is the machine-account `$` read out of the requester field and on to the wrong one: in this tenant `service_name` is the SPN, so there is no suffix to match. Check it with the probe in **Before turning it on** before you deploy anything built on a suffix.

Run every 10 minutes over the last 15. The window is the rate control - shorten it or lengthen it, but measure the threshold for the window you choose. Overlapping runs re-count the same burst, which is why suppression is 6h.

## Query
```esql
FROM logs-yourorg-microsoft-windows*
// 4769 = a service ticket was handed out. 0x0 and 0x00000000 are the same success in different pipelines.
| WHERE event.code == "4769"
  AND winevt.event_data.status IN ("0x0", "0x00000000")
// Machine requesters ask for host tickets by design (HOST$, HOST$@DOMAIN). Nothing in the event says
// "machine account", so this is a leading-wildcard LIKE on purpose; IS NULL keeps a row whose requester
// field is missing instead of dropping it without a trace.
  AND (user.name IS NULL
       OR (NOT user.name LIKE "*$" AND NOT user.name LIKE "*$@*"))
// Sanctioned collectors and scanners as account + address pairs (placeholders, repeat the clause per pair).
// Both fields, so the same account borrowed by an attacker from anywhere else still alerts.
  AND NOT (user.name == "<collector_account>" AND source.ip == "<collector_ip>")
// Group key normalised in place, and a missing requester stays visible as its own group
| EVAL user.name = TO_LOWER(COALESCE(user.name, "unknown-requester"))
// One row per account over the whole window: no hour bucket, so a burst that straddles the boundary
// is not split into two halves that each sit under the threshold.
| STATS computers = COUNT_DISTINCT(winevt.event_data.service_name, 4000),
        sample = TOP(winevt.event_data.service_name, 10, "asc"),
        addrs = COUNT_DISTINCT(source.ip),
        enc = MV_SLICE(VALUES(winevt.event_data.ticket_encryption_type), 0, 4),
        dcs = COUNT_DISTINCT(host.name),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY user.name
// 40 distinct SPNs in 15 minutes is a starting value: a collection run is hundreds inside seconds, the
// busiest legitimate account in a real estate is single digits per quarter hour. Replace it with the
// p99 from the Baseline query below, or let the account baseline itself do it (Baseline, Tier 2).
| WHERE computers >= 40
| EVAL span_s = DATE_DIFF("second", first_seen, last_seen)
| SORT computers DESC
| LIMIT 100
```

`computers` counts **distinct SPNs**, not distinct hosts: one computer can answer to `HOST/`, `RestrictedKrbHost/` and `TERMSRV/`, so a sweep of 40 hosts can read 40-120. That inflation is the same for attacker and admin, so the threshold holds - it just means the number is "services reached", not "machines touched". `sample` is bounded and alphabetical, not the worst ten; the pivot query below finds the rest.

## Baseline
One query over the last 7 days at the rule's window. Nothing is filtered before the second `STATS` on purpose - a pre-filter hides every account whose peak is under the threshold, which is exactly the population the threshold has to clear. Percentiles are over **active** buckets only: a quarter hour with no ticket requests produces no row, so `active_buckets` says how much of the week the account was actually seen.
```esql
FROM logs-yourorg-microsoft-windows*
// the rule's gate, unchanged (the same leading-wildcard machine exclusion)
| WHERE event.code == "4769"
  AND winevt.event_data.status IN ("0x0", "0x00000000")
  AND (user.name IS NULL
       OR (NOT user.name LIKE "*$" AND NOT user.name LIKE "*$@*"))
| EVAL user.name = TO_LOWER(COALESCE(user.name, "unknown-requester")),
       bucket = DATE_TRUNC(15 minutes, @timestamp)
| STATS computers = COUNT_DISTINCT(winevt.event_data.service_name, 4000) BY user.name, bucket
// this is the baseline: no threshold on `computers` here, because filtering first would hide the accounts
// this query exists to measure
| STATS active_buckets = COUNT(*),
        p50 = PERCENTILE(computers, 50),
        p95 = PERCENTILE(computers, 95),
        p99 = PERCENTILE(computers, 99),
        peak = MAX(computers),
        hot_buckets = COUNT(*) WHERE computers >= 40
    BY user.name
| SORT peak DESC
| LIMIT 50
```
Read it as: `p99` single digits and `peak` in the hundreds means a human whose worst quarter hour is normal - exclude the account **and its address** as a pair. `peak` of 200+ is a scanner or management tool. Set the rule's threshold above the highest legitimate `p99` and well below a real collection run.

The cheapest alternative is to let the rule baseline itself: deploy it at `>= 40` with notifications off for a week, then read the alerts.

## Baseline, Tier 2: let each account carry its own threshold
A fixed number still needs a list of exceptions, and a list of exceptions is what an attacker borrows. Turning the baseline into a per-account threshold removes both: a scanner's p99 raises its own bar out of the way, and an account that never sweeps anything needs to reach 30 to alert at all.

Transform, every 30 minutes over the last 30 days, into `ticket_baseline` (lookup index mode, keyed on `user.name`):
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE event.code == "4769"
  AND winevt.event_data.status IN ("0x0", "0x00000000")
// same leading-wildcard machine exclusion as the rule, for the same reason
  AND (user.name IS NULL
       OR (NOT user.name LIKE "*$" AND NOT user.name LIKE "*$@*"))
| EVAL user.name = TO_LOWER(COALESCE(user.name, "unknown-requester")),
       bucket = DATE_TRUNC(15 minutes, @timestamp)
| STATS computers = COUNT_DISTINCT(winevt.event_data.service_name, 4000) BY user.name, bucket
// second STATS on purpose: the first one measures each quarter hour, this one turns 30 days of them into
// one threshold per account, which is what the rule compares a burst against
| STATS p99 = PERCENTILE(computers, 99), peak = MAX(computers), active_buckets = COUNT(*) BY user.name
// three times the account's own 99th-percentile quarter hour, and never below 30
| EVAL threshold = CASE(p99 * 3 > 30, p99 * 3, 30)
| KEEP user.name, threshold, p99, peak, active_buckets
```
The rule then stops carrying a number of its own. Everything above the `STATS` is identical; add the join and replace the threshold:
```esql
| LOOKUP JOIN ticket_baseline ON user.name
// an account with no baseline yet falls back to the fixed starting value
| WHERE (threshold IS NULL AND computers >= 40) OR (threshold IS NOT NULL AND computers >= threshold)
```
`LOOKUP JOIN` needs the target index in `lookup` mode and Elastic 9.x (tech preview in late 8.x) - confirm the version. Until the transform has run once, or for an account created yesterday, the fallback number is what protects you.

## Optional: the target side (5140)
If you collect **Audit File Share** (5140) from your servers and workstations, the same sweep shows there as IPC$ opened on many computers - and it also catches a collector running over NTLM, which raises no 4769. Run it the same way; it only counts targets whose Security log you actually collect, so with workstation logs missing the 4769 side does the work.
```esql
FROM logs-yourorg-microsoft-windows*
// IPC$ opened on many computers by a user account (LIKE, so the \\host\ part is a wildcard)
| WHERE event.code == "5140"
  AND winevt.event_data.share_name LIKE "\\\\*\\IPC$"
  AND (user.name IS NULL OR (NOT user.name LIKE "*$" AND NOT user.name LIKE "*$@*"))
| EVAL user.name = TO_LOWER(COALESCE(user.name, "unknown-requester"))
| STATS computers = COUNT_DISTINCT(host.name, 4000),
        sample = TOP(host.name, 10, "asc"),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY user.name
// same 40-target starting value and the same 15-minute window as the 4769 rule - baseline it the same way
| WHERE computers >= 40
| SORT computers DESC
| LIMIT 100
```

## Which host and process sent it
Falcon, for the alert's address only, so it's cheap. No rows means the address isn't a managed host (the attacker's own machine, or a device behind a proxy - check 05 on the hosts around it). SharpHound's SMB goes through the kernel and shows as `System`; its LDAP (389/9389) shows the tool, `sharphound.exe` or `powershell.exe` - which 24 catches as a directory sweep.
```esql
FROM logs-yourorg-crowdstrike-data-default*
// one address from the alert (expand TOP(source.ip) from the alert row); leading wildcard is not needed here
| WHERE event.action == "networkconnectip4" AND source.ip == "<source.ip>"
  AND destination.port IN (88, 389, 445, 636, 3268, 3269, 9389)
| STATS connections = COUNT(*), ports = VALUES(destination.port), first_seen = MIN(@timestamp)
    BY host.name, data.ContextBaseFileName
```
```logscale
#event_simpleName=NetworkConnectIP4 LocalAddressIP4="<source.ip>" RemotePort=in([88, 389, 445, 636, 3268, 3269, 9389])
| default(field=ContextBaseFileName, value="unknown")
| groupBy([aid, ContextBaseFileName], function=[count(as=connections), collect([RemotePort], limit=10)], limit=max)
| match(file="aid_master_main.csv", field=aid, include=[ComputerName])
| select([ComputerName, ContextBaseFileName, connections, _collect])
```

## Before turning it on
- **Audit Kerberos Service Ticket Operations** (Success) on every DC, or there is no 4769 to count.
- **Confirm `service_name` really is the SPN** in your pipeline before trusting anything that pattern-matches it. Values should look like `HOST/DC01`, `MSSQLSvc/…`, `krbtgt`:
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE event.code == "4769" AND winevt.event_data.status IN ("0x0", "0x00000000")
| STATS n = COUNT(*) BY winevt.event_data.service_name
| SORT n DESC
| LIMIT 20
```
- **Confirm the requester shapes** your machines use, so the exclusion in the gate is the right one. If machine accounts arrive as `HOST$@DOMAIN` only, `*$` is redundant but harmless; if they arrive as `HOST$`, `*$` is what keeps them out:
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE event.code == "4769"
| STATS n = COUNT(*) BY user.name
| SORT n DESC
| LIMIT 20
```
- Put every account from the baseline that legitimately crosses the threshold into the gate as an **account + address pair** - give it both fields, since a sanctioned collector account is exactly the one an attacker would borrow.
- Set the suppression key to `user.name`; it is the only entity that survives the `STATS`, and it is what a re-run of the same sweep folds into.
- Proxy and NAT: `source.ip` is the Kerberos client address the DC recorded, so a collector behind a SOCKS proxy appears as the proxy's address. The account is still the entity the rule decides on.

## What it misses
- SharpHound from the attacker's own machine over NTLM, or `bloodhound.py` without `-k`: no 4769. The optional 5140 companion catches it where you audit file shares; 05 sees the proxy on the pivot; 24 sees the LDAP/ADWS collection.
- LDAP-only (`-c DCOnly`) and Stealth collection, which skip most computers - 24 covers the directory read.
- A sweep throttled under the threshold inside the window. The Tier 2 account baseline catches slow runs better than a fixed number, because it compares the account against itself; a genuinely slow run spread across many days still needs a daily rule at a lower threshold, baselined the same way.
- A run split across **several accounts**, each staying under its own threshold. The entity is the account, so this needs a host-level or destination-level view (5168, or 5140 grouped by `host.name` across accounts) rather than a bigger threshold.
- Ticket requests answered from a DC you don't collect 4769 from, and cross-forest tickets requested in another domain.

## When it fires
Run the pivot query for an address from the alert. A managed host with `sharphound.exe`, `powershell.exe` or an unknown binary on 389/9389 is the collector; look on it for the output (a zip of JSON) and treat the account as compromised until the run is explained. No managed host means the attacker's machine or a proxy: check 05 on the hosts around it.
