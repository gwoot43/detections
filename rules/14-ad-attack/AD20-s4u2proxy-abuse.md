---
id: AD20
name: S4U2Proxy - an account presenting transited Kerberos tickets to services it is not delegated to
category: ad-attack
status: todo
language: esql
index: logs-yourorg-microsoft-windows*
mitre: [T1550.003, T1134.001]
data_source: Windows Security event 4769 on domain controllers (TransitedServices populated)
suppression:
  fields: [user.name]
  duration: 24h
  missing_fields: do_not_suppress
---

## Why this is high fidelity

Kerberos delegation has two halves. `S4U2Self` lets any service ask the KDC for a ticket **to itself** on behalf of
any user - no delegation rights required. `S4U2Proxy` then lets that service hand the user's ticket to a **second**
service and receive a ticket to it. That second step only succeeds when the requesting service is trusted to
delegate, either through constrained delegation (`msDS-AllowedToDelegateTo` on the service) or resource-based
constrained delegation (`msDS-AllowedToActOnBehalfOfOtherIdentity` on the target computer).

Whoever controls such a service becomes **any user** to the target - including a domain administrator to a DC's
LDAP or CIFS SPN. Two ways in: compromise a service that already delegates, or grant yourself the right, which
takes only `GenericWrite` on a computer object.

The proxied ticket carries its chain in `TransitedServices`. `AD08` deliberately excludes those rows - it reads a
non-empty `TransitedServices` as "normal delegation" and looks only at tickets with no TGT behind them. That
leaves the abuse case unread by any rule in the catalogue, which is what this one covers.

## Query

```esql
FROM logs-yourorg-microsoft-windows*
| WHERE @timestamp >= NOW() - 1 hour
  AND event.code == "4769"
| EVAL svc = TO_LOWER(COALESCE(winevt.event_data.service_name, "")),
       impersonated = TO_LOWER(COALESCE(winevt.event_data.target_user_name, "")),
       transited = TO_LOWER(COALESCE(TO_STRING(winevt.event_data.transited_services), "-")),
       etype = TO_LOWER(TO_STRING(winevt.event_data.ticket_encryption_type)),
       ip = TO_STRING(winevt.event_data.ip_address)
// a proxied ticket: the chain is non-empty. "-" is a plain TGS request, which AD08 already covers.
| WHERE transited != "-" AND transited != "" AND svc != ""
// a service ticket for the service's own account is S4U2Self, which needs no delegation rights. The proxy step is
// the ticket to a *different* service, so drop the self-case here.
  AND NOT transited LIKE "*" || svc || "*"
| STATS tickets = COUNT(*),
        services = COUNT_DISTINCT(svc, 4000),
        users = COUNT_DISTINCT(impersonated, 4000),
        rc4 = COUNT(*) WHERE etype == "0x17",
        service_sample = MV_SLICE(VALUES(svc), 0, 5),
        user_sample = MV_SLICE(VALUES(impersonated), 0, 5),
        sources = MV_SLICE(VALUES(ip), 0, 5),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY host.name, transited
// A legitimately delegating service produces one fixed pair - (service, target SPN) - and the same users every
// day. Proxying to two or more distinct services from one intermediate is either a delegation change or abuse.
// Baseline: run the pair query below for two weeks and allowlist the (transited, svc) pairs it returns.
| WHERE services >= 2
| SORT services DESC
| LIMIT 50
```

The `NOT transited LIKE "*" || svc || "*"` clause is the S4U2Self exclusion. It concatenates the target SPN into the
pattern rather than hard-coding it, so a renamed service account keeps working.

## Reading the alert

`transited` is the **intermediate service** that requested the ticket; `svc` is the service the ticket is for;
`impersonated` is the user whose identity was borrowed. Read it as
`transited` proxied `impersonated` to `svc`.

- `services >= 2` with `users` large is a delegation grant being used broadly - start with who changed delegation.
- `rc4` non-zero on a transited ticket is a downgrade and worth its own look: modern estates negotiate AES, and an
  attacker who cannot get an AES key asks for RC4.
- One `impersonated` account reaching a high-value `svc` (a DC's LDAP/CIFS SPN, a backup service) is the case that
  matters, even at `services == 1`. The threshold is the default, not the only rule.

## Nearest benign twins

- **A real multi-tier application** (web tier delegating to a database, a reporting service to SQL). It produces
  the same pair every day with the same population - the pair baseline, not the event, is what separates them.
- **RBCD set by an admin** during a legitimate migration. Rare, change-ticketed, and it shows up as a `5136` write
  on the target computer object (`I14`), which is why the two rules are worth reading together.
- **Backup and monitoring products** that use delegation to read SMB shares. Allowlist by the intermediate's
  account, not by target.

## What it misses

- **The S4U2Self step alone.** It needs no delegation right, so an attacker using it to escalate locally leaves no
  transited chain. Only the proxy step is visible here.
- **Delegation that was granted long ago.** This rule cannot tell "was always delegated" from "should not be
  delegated" - that is `I14`'s job at configuration time, and the pair baseline's job afterwards.
- **Non-DC collection.** `4769` is written by the KDC. If the DC's log does not reach
  `logs-yourorg-microsoft-windows*`, this rule has nothing to read - run the probe below first.

## Baseline

Two weeks of pairs, to allowlist what legitimately delegates:

```esql
FROM logs-yourorg-microsoft-windows*
| WHERE @timestamp >= NOW() - 14 days
  AND event.code == "4769"
| EVAL svc = TO_LOWER(COALESCE(winevt.event_data.service_name, "")),
       transited = TO_LOWER(COALESCE(TO_STRING(winevt.event_data.transited_services), "-"))
| WHERE transited != "-" AND transited != "" AND svc != ""
| STATS tickets = COUNT(*), days = COUNT_DISTINCT(BUCKET(@timestamp, 1 day)),
        users = COUNT_DISTINCT(TO_LOWER(COALESCE(winevt.event_data.target_user_name, "")), 4000)
    BY transited, svc
| SORT tickets DESC
| LIMIT 200
```

Anything that appears on most days is real delegation. Anything seen once, or appearing after a `5136` change on
the target computer object, is the case to look at.

## Test

```esql
FROM logs-yourorg-microsoft-windows*
| WHERE @timestamp >= NOW() - 24 hours AND event.code == "4769"
| STATS tickets = COUNT(*), transited_present = COUNT(*) WHERE winevt.event_data.transited_services IS NOT NULL,
        transited_dash = COUNT(*) WHERE TO_STRING(winevt.event_data.transited_services) == "-"
```

If `transited_present` is zero, the field is not being collected and this rule cannot fire - stop and fix ingest
before tuning anything.
