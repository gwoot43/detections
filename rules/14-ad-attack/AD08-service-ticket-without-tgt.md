---
id: AD08
name: Kerberos service tickets used by an account with no TGT issued (possible forged golden ticket)
category: ad-attack
status: todo
rank: 8
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1558.001]
data_source: Windows Security events 4768, 4769 and 4770 from all domain controllers
suppression:
  fields: [acct]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A forged TGT is created offline with the stolen krbtgt key, so the domain controller never issues it and never logs a 4768 for it. The forger then requests service tickets (4769) normally. A genuine user can only request service tickets while holding a valid TGT, and with the default 10-hour TGT lifetime that means a 4768 (issued) or 4770 (renewed) within the previous 10 hours. So an account requesting service tickets in the last hour with no TGT issued or renewed in the 11 hours before it is using a ticket the domain did not issue.

## Prerequisite
4768, 4769 and 4770 must be collected from every domain controller. A TGT issued by a DC you do not collect from looks exactly like a forged one. Check your maximum user-ticket lifetime: if it is longer than 10 hours, widen the lookback to match.

## Query
Run hourly with an 11-hour lookback.
```esql
FROM logs-system.security*, logs-windows.forwarded*
| WHERE event.code IN ("4768", "4769", "4770")
| EVAL acct = TO_LOWER(MV_FIRST(SPLIT(COALESCE(TO_STRING(winlog.event_data.TargetUserName), ""), "@"))),
       svc = TO_LOWER(COALESCE(TO_STRING(winlog.event_data.ServiceName), "")),
       transited = COALESCE(TO_STRING(winlog.event_data.TransitedServices), "-"),
       status = TO_STRING(winlog.event_data.Status)
// 4770 has no Status field (it is logged only on success), so it must not be filtered on status
| WHERE acct != "" AND NOT ENDS_WITH(acct, "$") AND (status == "0x0" OR event.code == "4770")
| STATS recent_tgs = SUM(CASE(event.code == "4769" AND transited == "-" AND @timestamp >= NOW() - 1 hour, 1, 0)),
        // a TGT issued (4768) or a TGT renewed (4770 for krbtgt); other 4770s renew service tickets
        tgt_events = SUM(CASE(event.code == "4768" OR (event.code == "4770" AND svc LIKE "krbtgt*"), 1, 0)),
        services = VALUES(CASE(event.code == "4769", svc, NULL)),
        sources = VALUES(source.ip),
        domains = VALUES(TO_STRING(winlog.event_data.TargetDomainName))
    BY acct
| WHERE recent_tgs > 0 AND tgt_events == 0
```
Only service tickets from the last hour are tested, against TGT activity across the whole 11 hours. That way every tested ticket has a full ticket lifetime of history behind it, and a TGT issued just before the window cannot cause a false alert.

## Suppression
Suppress by `acct` for 24h. Alerts missing a key field are not suppressed. Aggregating rule; a forged ticket is reused for hours.

## Known false positives / exclusions
- Accounts from trusted domains get their TGTs from their own domain's DCs. Restrict to your own domain by filtering `domains`, or exclude the trusted domain names inline.
- Missing DC logs, as above. This is the main cause of noise; fix collection rather than excluding.
- Delegation flows are excluded through `TransitedServices`. Baseline for two weeks before enabling.

## Coverage limits
- This does not catch diamond or sapphire tickets, which are built from a genuinely issued TGT, nor silver tickets, which never touch the domain controller.
- The forger must have the krbtgt key, so also check for its theft: I01 (DCSync), WE09 (NTDS.dit), AD01 (DCShadow).

## Triage
- Confirm the account and its sources. If no TGT gap explains it, treat the krbtgt key as compromised: plan a double krbtgt reset and hunt for how the key was taken.

## Test
Validate on historical data: the rule should be silent for normal users once collection from every DC is confirmed.
