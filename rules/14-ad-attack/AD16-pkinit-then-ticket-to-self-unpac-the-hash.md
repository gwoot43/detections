---
id: AD16
name: Certificate logon followed by a ticket to itself (UnPAC-the-hash - Certipy auth, Rubeus /getcredentials)
category: ad-attack
status: todo
rank: 16
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1649, T1558]
data_source: Domain controller events 4768 (PKINIT) and 4769 (user-to-user service ticket)
suppression:
  fields: [account_sid]
  duration: 1h
  missing_fields: do_not_suppress
---
`certipy auth` logs on with the certificate (PKINIT, a 4768 with a certificate pre-auth type), then straight away asks the same DC for a ticket to itself, user-to-user (a 4769 whose service is the account itself). That second step is how it pulls the account's NT hash out of the ticket, and Certipy does it by default. Rubeus `asktgt /getcredentials` does the same. Windows never does: a smartcard or Windows Hello logon is a 4768 followed by tickets to real services.

So the pair is the finding: a certificate logon and a ticket to itself, for the same account, from the same address, on the same DC, within the 10 minutes the rule looks at. It doesn't matter which template, which ESC, or whether the certificate was forged.

Run every 5 minutes over the last 10.
```esql
FROM logs-system.security*, logs-windows.forwarded*
| WHERE winlog.event_data.Status == "0x0"
  AND ((event.code == "4768" AND winlog.event_data.PreAuthType IN ("15", "16", "17"))
       OR (event.code == "4769" AND winlog.event_data.TicketOptions IN ("0x40810008", "0x40810018")))
// The account is TargetSid on the logon and ServiceSid on the ticket, so a ticket to itself lands in the same group.
| EVAL account_sid = COALESCE(winlog.event_data.TargetSid, winlog.event_data.ServiceSid)
| STATS cert_logons = COUNT(*) WHERE event.code == "4768", tickets_to_self = COUNT(*) WHERE event.code == "4769",
        first_seen = MIN(@timestamp), account = VALUES(winlog.event_data.TargetUserName),
        cert_issuer = VALUES(winlog.event_data.CertIssuerName), cert_serial = VALUES(winlog.event_data.CertSerialNumber)
    BY account_sid, winlog.event_data.IpAddress, winlog.computer_name
// Both in the window is the finding: no count threshold to baseline.
| WHERE account_sid IS NOT NULL AND cert_logons > 0 AND tickets_to_self > 0
| KEEP first_seen, account, account_sid, winlog.event_data.IpAddress, winlog.computer_name, cert_issuer, cert_serial,
       cert_logons, tickets_to_self
```
No LogScale version: the domain controllers' logs are in Elastic. Suppress by `account_sid` for an hour.

## Before turning it on
- 4768 and 4769 from every DC, success auditing on "Kerberos Authentication Service" and "Kerberos Service Ticket Operations".
- The two `TicketOptions` values are the user-to-user requests Certipy and Rubeus send (forwardable, renewable, canonicalize, enc-tkt-in-skey, with or without renewable-ok). Run `certipy auth` once in a lab and check the 4769 shows one of them.
- Run it over 30 days. It should return nothing; anything it does return is worth reading before you exclude it.

## What it misses
- `certipy auth -no-hash`, or a certificate used only for its TGT. AD15 still sees the first certificate logon.
- A certificate used over LDAPS or Schannel instead of Kerberos (`certipy auth -ldap-shell`, PassTheCert): no 4768 at all.
- A DC whose Security log isn't collected.

## When it fires
Treat the account as compromised: the attacker has its TGT and NT hash. Reset its password, revoke the certificate by `cert_serial`, and find where it came from: AD14 and I09 on the CA, AD15 for other certificate logons from the same address, AD06 for template changes. `IpAddress` is the attacker's box; it's often not domain-joined.
