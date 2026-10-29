---
id: D01
name: Honey AD account kerberoasted - a service ticket requested for a honey SPN (4769)
category: deception
status: todo
rank: 1
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1558.003, T1078.002]
data_source: Domain controller Security log. 4769.
suppression:
  fields: [honey_account]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
A honey account has no owner, no service and no reason to be touched. Give it a Service Principal Name and it becomes a kerberoast lure: the only way to get a service ticket for it is to ask for one, and the only reason to ask is to crack it offline. So **one** 4769 naming the honey SPN is an attacker kerberoasting, full stop - a single event, on the domain controller, no counting.

This is the deception counterpart to I03/I04, which look for roasting **volume and weak encryption** across real accounts. This fires on one request for an account that should never be requested.

## Prerequisite
- DCs: **Audit Kerberos Service Ticket Operations** (Success). That one subcategory is all this needs.
- Create the honey account as a normal user with an SPN set (so it is roastable), no real service behind it, and a strong random password so a crack never succeeds.
- Replace the placeholder names with your honey accounts **in the deployed Elastic rule only** - don't commit real names to this repo (see the README on keeping the traps secret).

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded* METADATA _id, _index, _version
| WHERE event.code == "4769"
| EVAL honey_account = TO_LOWER(COALESCE(winlog.event_data.ServiceName, ""))
// honey SPN accounts, one per lure if you run several (placeholders); sAMAccountName in lowercase
| WHERE honey_account IN ("<honey_kerberoast>", "<honey_kerberoast_2>")
| EVAL requester = TO_LOWER(COALESCE(winlog.event_data.TargetUserName, "")),
       from_ip = COALESCE(TO_STRING(source.ip), winlog.event_data.IpAddress)
| KEEP @timestamp, honey_account, requester, from_ip, winlog.event_data.TicketEncryptionType,
       winlog.event_data.TicketOptions, winlog.computer_name, _id, _version, _index
```
`requester` is the account that asked for the ticket and `from_ip` where it came from. `TicketEncryptionType` `0x17` (RC4) is the classic roast-friendly request, but any value is still a hit - nothing should ask for this ticket at all.

## Suppression
Suppress by `honey_account` for 1h. Alerts missing a key field are not suppressed. One roasting run produces a burst of 4769s for the SPN; a request an hour later alerts again.

## Known false positives / exclusions
- **Your own audit tooling** (PingCastle, Purple Knight, a kerberoast audit script, security-team BloodHound collection). Agree a schedule and exclude that tool's `requester` and `from_ip`, or simply expect the alert and close it.
- **Vulnerability scanners with a Kerberos check.** Exclude the scanner's IP.
- Nothing else should request this ticket. If something does, find out what before excluding it.

## Other honey-account traps (each one more event code)
Kept out to stay a single-event rule. Add the one you deploy:
- **AS-REP roast** (a honey account with pre-auth disabled): `event.code == "4768" AND winlog.event_data.PreAuthType == "0"`, honey name in `TargetUserName`.
- **Credential lures** (a honey password planted in a description field, a SYSVOL script, LSASS): someone trying it shows as a logon or auth attempt - `4624`/`4625`/`4648` (member servers), `4771`/`4776` (DC) with the honey name in `TargetUserName`. Keep each as its own rule so the index read and the subcategory stay minimal.

## Triage
- Treat as a confirmed intrusion or red-team action. Identify `from_ip` and `requester`, contain the source host with Falcon, and check the requester account for compromise (I06, X02).
- Map the honey account back to its lure location using the restricted deception register, so you know what the attacker read and can reconstruct their path.

## Test
From a lab domain-joined host: `Rubeus.exe kerberoast /user:<honey_kerberoast> /nowrap`, or Impacket `GetUserSPNs.py -request-user <honey_kerberoast>`. Either should fire one alert.
