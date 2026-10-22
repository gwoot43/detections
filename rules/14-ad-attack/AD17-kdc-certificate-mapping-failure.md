---
id: AD17
name: Domain controller refused a certificate logon - certificate belongs to another account, has no strong mapping, or predates the account (Kdcsvc 39, 40, 41)
category: ad-attack
status: todo
rank: 17
language: esql
index: logs-system.system*
mitre: [T1649]
data_source: Domain controller System log, Kerberos KDC events 39, 40 and 41
suppression:
  fields: [winlog.computer_name, event.code]
  duration: 1h
  missing_fields: do_not_suppress
---
Since the 2022 certificate-mapping changes (KB5014754), the KDC checks that a logon certificate really belongs to the account it names, and it logs when it can't:

- **41: the certificate carries a different account's SID.** A certificate issued to one account being used to log on as another. That's a certificate requested while an account's UPN was swapped (the ESC9/ESC10 trick), ESC1 with the wrong `-sid`, or a forged certificate. Close to certain.
- **39: no strong mapping.** No SID in the certificate and no explicit mapping. Under full enforcement, the default since 2025, the logon is refused. An attacker's certificate from an ESC1, ESC9 or ESC16 path without a SID lands here; so does a legacy certificate nobody reissued.
- **40: the certificate is older than the account.** An account deleted and recreated under the same name, then logged on with a certificate from before.

Failed attempts count: Certipy prints the error and the attacker tries again with `-sid`, by which time this has fired.

Run every 5 minutes over the last 10.
```esql
FROM logs-system.system* METADATA _id, _index, _version
| WHERE event.code IN ("39", "40", "41")
  AND winlog.provider_name IN ("Microsoft-Windows-Kerberos-Key-Distribution-Center", "Kdcsvc")
| EVAL reason = CASE(event.code == "41", "CERTIFICATE SID BELONGS TO ANOTHER ACCOUNT",
                     event.code == "39", "NO STRONG MAPPING",
                     event.code == "40", "CERTIFICATE OLDER THAN ACCOUNT")
| KEEP @timestamp, winlog.computer_name, event.code, reason, message, _id, _index, _version
```
No LogScale version: the domain controllers' logs are in Elastic. Suppress by DC and event for an hour.

## Before turning it on
- Check the provider name your DCs log under: event IDs 39 to 41 are reused by other providers in the System log.
  ```esql
  FROM logs-system.system*
  | WHERE event.code IN ("39", "40", "41")
  | STATS events = COUNT(*), dcs = COUNT_DISTINCT(winlog.computer_name) BY winlog.provider_name, event.code
  ```
- Run it over 30 days. Any 41 needs explaining. A 39 that repeats daily for one account is a legacy certificate (an old smartcard, a device with a third-party certificate): have it reissued, or exclude that account for 39 only, never the whole event.

## What it misses
- A certificate that maps strongly: Certipy with the right `-sid`, a golden certificate with the right SID, shadow credentials (key trust). AD15 and AD16 see those logons.
- Certificate logons over Schannel (LDAPS), which log on the DC's Schannel side, not here.

## When it fires
The account in `message` is the target; the certificate's subject and issuer are in it too. Find the request on the CA (AD14, I09) and who asked for it, revoke the certificate, and look for 4768 logons from the same address (AD15, AD16), in case a retry with a SID worked.
