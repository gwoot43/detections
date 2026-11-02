# Certificate logon followed by a ticket to itself (UnPAC-the-hash)

`certipy auth` logs on with a certificate — PKINIT, a **4768** with a certificate pre-auth type — and then immediately asks the same DC for a service ticket **to the account itself**, user-to-user. That second ticket is how the account's NT hash is pulled out of the PAC, and `certipy auth` does it by default. Rubeus `asktgt /getcredentials` does the same. Windows never does: a smartcard or Windows Hello logon is a 4768 followed by tickets to *real* services.

`rules/14-ad-attack/AD16` has the pair exactly right, and the SID trick that makes it work is worth restating: 4768 records the authenticating account in **`TargetSid`**, and 4769 records the *service's* account in **`ServiceSid`** — so a ticket to itself lands both events in the same group, with no join and no name matching.

```esql
FROM logs-yourorg-microsoft-windows*
// 10 minutes in the query: the two events are seconds to a minute apart; a wider window only adds unrelated
// pairs from the same account.
| WHERE @timestamp >= NOW() - 10 minutes
  AND event.code IN ("4768", "4769")
// The two event-data fields are cast once here rather than inside the gate, so the gate stays index-answerable.
| EVAL preauth = TO_STRING(winevt.event_data.pre_auth_type),
       ticket_options = TO_STRING(winevt.event_data.ticket_options)
// PreAuthType 15/16/17 are the PKINIT variants (certificate pre-authentication). Verify against a real
// smartcard logon in your estate before trusting the list - the numbers differ by Windows build.
| WHERE winevt.event_data.status == "0x0"
  AND ((event.code == "4768" AND preauth IN ("15", "16", "17"))
       OR (event.code == "4769" AND ticket_options IN ("0x40810008", "0x40810018")))
// One SID for both halves: TargetSid on the logon, ServiceSid on the ticket.
| EVAL account_sid = COALESCE(TO_STRING(winevt.event_data.target_sid), TO_STRING(winevt.event_data.service_sid)),
       account = TO_LOWER(COALESCE(winevt.event_data.target_user_name, "")),
       client = winevt.event_data.ip_address
| STATS cert_logons = COUNT(*) WHERE event.code == "4768",
        self_tickets = COUNT(*) WHERE event.code == "4769",
        services = MV_SLICE(VALUES(winevt.event_data.service_name), 0, 4),
        issuers = MV_SLICE(VALUES(winevt.event_data.cert_issuer_name), 0, 2),
        serials = MV_SLICE(VALUES(winevt.event_data.cert_serial_number), 0, 2),
        first_seen = MIN(@timestamp), last_seen = MAX(@timestamp)
    BY account_sid, account, client, host.name
// Both halves in the same window on the same DC from the same address, for the same account: the finding.
// No threshold to baseline - the conjunction is the detection.
| WHERE account_sid IS NOT NULL AND cert_logons >= 1 AND self_tickets >= 1
| SORT first_seen ASC
| LIMIT 100
```

Deploy every 5 minutes over the last 10. Suppress by `account_sid` for 1h.

## Reading the alert
- **`services`** must name the account itself. If it names `krbtgt` or a real service, the pair is a normal logon plus a normal ticket and the SID grouping caught something it should not have.
- **`issuers` and `serials`** are the certificate that did it: the template and CA are how you find whether it was ESC1 (anyone can request), ESC9/10 (UPN swapped) or a forged certificate.
- **`client`** is the attacker's address, which is the host to isolate first.
- **`first_seen`** at the same second as a 4769 is the automated tool; a human smartcard logon has a gap.

## Nearest benign twins
- **Smartcard and Windows Hello for Business logons**, which are 4768 with PKINIT followed by tickets to file servers, SQL, and `krbtgt` — not to the account itself. The self-ticket requirement is what separates them.
- **Certificate-based service authentication**, where a service logs on with a certificate and then requests a ticket to itself to access its own resources. Rare, but it exists: an entity pair on `account_sid` once confirmed.
- **A PKINIT logon during a certificate renewal**, where the account gets a fresh certificate and logs on. Only the ticket-to-self half is missing, so it does not fire.

## What it misses
- **A certificate logon that never asks for the self-ticket** — `certipy auth -no-hash` or a manual `Rubeus asktgt` without `/getcredentials`. The certificate was still used against you, and the only trace left is the 4768.
- **A password-based UnPAC or a plain PKINIT logon used for access rather than hash extraction.** `AD15` (first certificate logon for an account) covers the novelty angle.
- **A DC that does not log 4769**, where the second half is invisible. Probe it.
- **The certificate being requested**, which is `AD06`/`AD14`'s half of the chain.

## Probe before enabling
```esql
FROM logs-yourorg-microsoft-windows*
| WHERE @timestamp >= NOW() - 7 days AND event.code IN ("4768", "4769")
| STATS events = COUNT(*), first = MIN(@timestamp) BY event.code, winevt.event_data.pre_auth_type
| SORT events DESC
| LIMIT 20
```
If no 4768 carries a `PreAuthType` of 15/16/17 despite smartcards being in use, the field is not being populated and the first half of the pair never matches.

## Pipeline
DC and AD events come from `logs-yourorg-microsoft-windows*` with `winevt.event_data.*` - the only Windows
source in this estate, for every channel. Keys are snake_case here; the ones this rule depends on are worth
confirming before it is trusted, because a renamed key returns null and the rule then matches nothing instead
of failing.

## References
- `rules/14-ad-attack/AD16-pkinit-then-ticket-to-self-unpac-the-hash.md` - the rule this refines
- `rules/14-ad-attack/AD15-first-certificate-logon-for-account.md` - the novelty view of the same first half
- MITRE T1649 (steal or forge authentication certificates), T1558 (Kerberos ticket abuse)
