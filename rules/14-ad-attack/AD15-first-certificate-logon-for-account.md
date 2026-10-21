---
id: AD15
name: First certificate logon (PKINIT) for an account in 30 days - a stolen or forged certificate in use, domain controllers especially
category: ad-attack
status: todo
rank: 15
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1649, T1550, T1078.002]
data_source: Windows Security 4768 on every domain controller
suppression:
  fields: [account]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
**One question:** is an account logging on with a certificate when it never does? Every AD CS attack ends the same way: the attacker logs on with the certificate. Certipy `auth` and Rubeus `asktgt /certificate` ask a domain controller for a Kerberos ticket using the certificate instead of a password (PKINIT). The DC logs it as event 4768 with a certificate pre-authentication type. That covers every way the certificate was obtained:
- a SAN placed inside the request (ESC1), which I09 can't see in the CA's events;
- an enrolment agent (ESC3), a weakened template or CA (ESC4, ESC6, ESC7: AD06, AD14), weak certificate mapping (ESC9, ESC10);
- a relayed domain controller (ESC8, ESC11: coerced with WE13, then a DC certificate issued to the attacker);
- a forged "golden" certificate signed with a stolen CA key (AD03), which never passes through the CA at all;
- shadow credentials (I12).

- **Anchor:** a successful Kerberos logon (4768) pre-authenticated with a certificate.
- **Corroborating property:** newness. Most accounts never log on with a certificate; the ones that do (smartcard or Windows Hello for Business key-trust users) do it every day, so they have a history and stay quiet. Computer accounts, domain controllers above all, log on with their passwords, so a computer account's certificate logon is the strongest form of this.
- **Exclusion:** none. Newness replaces an allowlist. Don't exclude by issuer: the attacker's certificate comes from your own CA.

## Query
Run hourly with a 30-day lookback.
```esql
FROM logs-system.security*, logs-windows.forwarded*
// 1 GATE: successful TGT requests pre-authenticated with a certificate (PKINIT: types 15, 16 and 17). Few accounts use
// certificates, so this is a small slice of Kerberos traffic. The account must be named.
| WHERE event.code == "4768" AND winlog.event_data.Status == "0x0"
  AND winlog.event_data.PreAuthType IN ("15", "16", "17")
  AND winlog.event_data.TargetUserName IS NOT NULL
// 2 SHAPE: the account name in one case: Kerberos logs it as the client sent it.
| EVAL account = TO_LOWER(winlog.event_data.TargetUserName)
// 3 REDUCE: per account, its first certificate logon in the 30 days, and where its certificate logons came from.
| STATS first_cert_logon = MIN(@timestamp), last_cert_logon = MAX(@timestamp), logons = COUNT(*),
        source_ips = COUNT_DISTINCT(winlog.event_data.IpAddress), sample_ips = TOP(winlog.event_data.IpAddress, 5, "asc"),
        issuers = VALUES(winlog.event_data.CertIssuerName), dcs = VALUES(winlog.computer_name)
    BY account
// 4 DECIDE: new for this account: its first certificate logon in 30 days happened in the last 2 hours.
| WHERE first_cert_logon >= NOW() - 2 hours
// 5 ENRICH: computer accounts (a trailing $), domain controllers above all, don't log on with certificates in normal use.
| EVAL account_type = CASE(ENDS_WITH(account, "$"), "computer", "user")
// 6 OUTPUT: the account, when, from where, and which CA issued the certificate.
| KEEP account, account_type, first_cert_logon, last_cert_logon, logons, source_ips, sample_ips, issuers, dcs
```
No LogScale version: the domain controllers' logs are in Elastic.

## Rule settings
| | |
|---|---|
| Interval / lookback | hourly / 30 days. The lookback is the history that newness is measured against, not a burst window; only first logons in the last 2 hours alert. |
| Suppression | `account` for 24h |

## Telemetry assumptions
- 4768 from **every** domain controller ("Audit Kerberos Authentication Service", success). A DC that isn't collected is a DC the attacker can use unseen.
- `PreAuthType` stored as the number Windows logs (`15`, `16`, `17` for certificates; `2` for a password). `CertIssuerName`, `CertSerialNumber` and `CertThumbprint` are filled on certificate logons.

Confirm both over the last day. Certificate types should be a small share, from a few accounts:
```esql
FROM logs-system.security*, logs-windows.forwarded*
| WHERE event.code == "4768"
| STATS logons = COUNT(*), accounts = COUNT_DISTINCT(winlog.event_data.TargetUserName), dcs = COUNT_DISTINCT(winlog.computer_name)
    BY winlog.event_data.PreAuthType
```

## Before enabling: who already uses certificates
Run the query over 30 days without the `first_cert_logon` filter and sort by `logons`. Those accounts are the population newness learns from: your smartcard and Windows Hello key-trust users. A computer account in that list is worth explaining now. If the list is empty, any certificate logon is new, and every alert is worth a look.

## Suppression
Suppress by `account` for 24h. Alerts missing a key field are not suppressed. Each account alerts once, on its first certificate logon; from then on it has a history.

## Known false positives / exclusions
- A user's first logon with a new smartcard or a new Windows Hello key-trust enrolment. One alert per user; S16 shows the Hello enrolment.
- A user returning after more than 30 days away. Their logons come from their usual machine; compare `sample_ips`.

## Blind spots
- **Certificate logons that skip Kerberos.** Authenticating to LDAPS with the certificate directly (Schannel, "PassTheCert") produces no 4768. AD02 and AD06 see what such a session changes.
- **Accounts that already use certificates.** A stolen certificate for a smartcard user blends into their history. Compare `sample_ips` with the user's usual machines.
- A domain controller whose Security log isn't collected.

## Triage
- **A computer account, above all a domain controller (`dc01$`):** treat it as a domain compromise in progress. The usual path is a relayed DC (WE13 for the coercion), a DC certificate from web enrolment, then DCSync with the DC's identity: look for replication from a non-DC address (AD02) right after `first_cert_logon`.
- **A user:** find the machine behind `sample_ips`. If it isn't theirs, find the certificate on the CA: a 4887 around that time whose subject names this user (I09, AD14). Certipy `auth` also recovers the account's password hash straight after: a 4769 from the same address whose service name is the account itself.
- Revoke the certificate, then reset the account. Resetting the password alone doesn't stop the certificate. If AD03 fired (the CA key was backed up), revocation won't help against a forged certificate: plan a CA rebuild.

## Test
In a lab with a vulnerable template, request a certificate for a second test account (`certipy req -template <vulnerable template> -upn testadmin@<lab domain>`), then `certipy auth -pfx testadmin.pfx`. The rule alerts for `testadmin` within the hour, and not again for the next 24 hours.
