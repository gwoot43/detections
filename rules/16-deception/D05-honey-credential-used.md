---
id: D05
name: Honey credential used - a decoy account planted in LSASS or a honey Domain Admin authenticates anywhere
category: deception
status: todo
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1003.001, T1550.002, T1078.002]
data_source: Windows Security 4624, 4625, 4648, 4768, 4771 and 4776 on domain controllers and servers
suppression:
  fields: [acct, source.ip]
  duration: 1h
  missing_fields: do_not_suppress
---

A honey credential is an account that exists, or looks like it exists, and is never used by anyone. Any
authentication attempt with it, successful or not, is someone who **found** it. There are two common ways to plant
one:

- **Decoy credentials in LSASS.** A scheduled task on chosen hosts runs `runas /netonly /user:<domain>\<honey_user>`
  with a fake password. The credential sits in LSASS memory and does nothing. An attacker who dumps LSASS (`W01`,
  item 8) sees it as a cached domain credential and tries it. The first failed logon or Kerberos request names the
  honey account, from the attacker's own source.
- **A honey Domain Admin.** A real but disabled or never-used account, with a convincing name and a membership that
  shows up in BloodHound paths. Recon (`B09`, item 15) finds it, and any attempt to use it fires here.

`D01` covers the kerberoast lure (a honey **SPN** being requested). This rule covers the honey **account** being
used. Together they catch credential dumping (item 8), kerberoasting (item 6) and AD recon (item 15) at close to zero
false positives.

## Query

Run every 5 minutes with a 10-minute lookback.

```esql
FROM logs-system.security*, logs-windows.forwarded* METADATA _id, _index, _version
| WHERE event.code IN ("4624", "4625", "4648", "4768", "4771", "4776")
| EVAL acct = TO_LOWER(COALESCE(winlog.event_data.TargetUserName, ""))
// honey accounts (placeholders): sAMAccountName in lowercase, one per lure
| WHERE acct IN ("<honey_lsass_user>", "<honey_domain_admin>")
| EVAL attempt = CASE(event.code == "4624", "logon_succeeded",
                      event.code == "4625", "logon_failed",
                      event.code == "4648", "explicit_credentials_used",
                      event.code == "4768", "kerberos_tgt_requested",
                      event.code == "4771", "kerberos_preauth_failed",
                      "ntlm_validation")
| KEEP @timestamp, attempt, acct, source.ip, winlog.computer_name, winlog.event_data.WorkstationName,
       winlog.event_data.LogonType, winlog.event_data.Status, winlog.event_data.SubjectUserName, _id, _version, _index
```

## Before turning it on

- **Choose names that fit the estate's own convention.** An obviously fake name (`honeyadmin`) is skipped by
  experienced operators.
- **Record where each lure is planted.** The LSASS decoy should go on a small, known set of hosts. The
  `source.ip` / `WorkstationName` in the alert then tells you which host was dumped, because the attacker uses the
  credential from where they found it or from their next hop.
- **Test it.** Run `runas /netonly` with the honey account from a lab host and confirm the `4625` / `4771` lands here.

## What it misses

- An attacker who dumps LSASS but never tries the credentials. Most do try, because a cached domain credential is the
  reason to dump.
- Credentials that are validated offline. A cracked hash of a honey account is not used until it is used.

## When it fires

There is no benign version. Treat the source host as compromised. The host where the LSASS decoy was planted, and
that the attempt traces back to, had its memory dumped: start the `W01` / `CS06` investigation there.
