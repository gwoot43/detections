# DC refused a certificate logon — wrong account, no strong mapping, or a certificate older than the account

Since the 2022 certificate-mapping changes (KB5014754), the KDC checks that a logon certificate belongs to the account it names, and logs when it cannot:

- **41** — the certificate carries **another account's SID**. A certificate issued to one account being used to log on as another: the ESC9/ESC10 UPN-swap trick, ESC1 with `-sid` pointing elsewhere, or a forgery. Close to certain.
- **39** — **no strong mapping**: no SID in the certificate and no explicit mapping. Under full enforcement (the default from 2025) the logon is refused.
- **40** — the certificate is **older than the account**: an account deleted and recreated under the same name, then logged on with the pre-existing certificate.

`rules/14-ad-attack/AD17` has the three events and the provider filter. This version drops the rendered `message` from the payload (the largest column in the index), extracts the **account** so the alert names who was refused, and says plainly which of the three is noise in a mixed-enforcement estate.

```esql
FROM logs-yourorg-microsoft-windows*
// One hour in the query: these are rare, and a refused logon arrives in bursts when an attacker retries.
| WHERE @timestamp >= NOW() - 1 hour
  AND event.code IN ("39", "40", "41")
// 39-41 are reused by other providers in the System log; the KDC is the only one that means this.
  AND winevt.provider_name IN ("Microsoft-Windows-Kerberos-Key-Distribution-Center", "Kdcsvc")
| EVAL reason = CASE(event.code == "41", "certificate_sid_is_another_account",
                     event.code == "40", "certificate_older_than_account",
                     "no_strong_mapping"),
       account = TO_LOWER(COALESCE(winevt.event_data.target_user_name, winevt.event_data.account_name, "")),
// 39 is the legacy-certificate population: in an estate that has not finished enforcement, stack it as its
// own row so 41 is not buried under it.
       severity = CASE(event.code IN ("40", "41"), "high", "triage") 
| STATS events = COUNT(*),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        dcs = COUNT_DISTINCT(winlog.computer_name)
    BY reason, severity, account
| SORT events DESC
| LIMIT 100
```

Deploy every 15 minutes over the last hour. Suppress by `reason` + `account` for 6h.

## Reading the alert
- **`severity = high`** is 40/41: the certificate named the wrong account, or predates it. Those two are worth a call in minutes — the certificate exists, and whoever holds it has tried to use it.
- **`reason = no_strong_mapping`** is the noisy one. In an estate mid-enforcement it is dominated by old certificates that were never reissued; in an estate at full enforcement it means the logon was refused and the certificate is attacker-made or unmanaged. The difference is a policy question, not a query one.
- **`account`** is who was refused. A Tier-0 account here is a much louder signal than a service account that was migrated last year.
- **`dcs`** above one means the attempt was tried against several DCs, which is what a tool does when the first one says no.

## Nearest benign twins
- **Legacy certificates issued before the mapping change.** The fix is reissue, not a suppression; track them as a count that should trend to zero.
- **A user with two accounts** (an admin account and a normal one) who logged on with a certificate issued to the other. It produces 41 legitimately, and it is the same shape as ESC9 — which is why it needs the person, not the tool.
- **Account recreation** after a deletion (a rehired user, a rebuilt service account) with an old certificate still on a smartcard. 40, benign, and fixed by reissuing.

## What it misses
- **Successes.** By definition this rule sees refusals. A certificate that maps correctly produces no event and lands in `pkinit-ticket-to-self` if it is being abused for hash extraction.
- **Enforcement disabled**, where 39 is logged but the logon is allowed anyway — the log then records a refusal that did not happen. Check your `StrongCertificateBindingEnforcement` value before trusting the 39 population.
- **Certificate issuance**, which is `AD06`/`AD14`; and the CA's own logs, which are a different provider entirely.

## Probe before enabling
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE @timestamp >= NOW() - 30 days AND event.code IN ("39", "40", "41")
| STATS events = COUNT(*), last = MAX(@timestamp) BY winevt.provider_name, event.code
| SORT events DESC
| LIMIT 20
```
The provider list is a filter, not a guess: if the codes appear only under other providers, your DCs are logging this somewhere else — or the KDC auditing is off and the rule is dead.

## Pipeline
DC and AD events come from `logs-yourorg-microsoft-windows*` - the only Windows source in this estate, for every
channel. Event data is under `winevt.event_data.*` in snake_case, and the event's own Computer field is
`winlog.computer_name`, **not** `host.name`: the two hold different values here, and `host.name` is the agent's
identity rather than the machine that logged the event. A key that does not exist returns null, so a renamed
field makes the rule match nothing instead of failing.

## References
- `rules/14-ad-attack/AD17-kdc-certificate-mapping-failure.md` - the rule this refines
- Microsoft KB5014754 - certificate-based authentication changes, `StrongCertificateBindingEnforcement` and the 39/40/41 semantics
- MITRE T1649 (steal or forge authentication certificates)
