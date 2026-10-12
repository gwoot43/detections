---
id: D01
name: Honey AD account touched (kerberoast of honey SPN, AS-REP roast, or any logon or authentication attempt with honey credentials)
category: deception
status: todo
severity: critical
rank: 1
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1558.003, T1558.004, T1078.002, T1110, T1552.001, T1003.001]
data_source: Domain controller and member server Security log. 4768, 4769, 4770, 4771, 4776, 4624, 4625, 4648.
suppression:
  fields: [honey_account, trap]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Honey accounts have no owner, no service and no reason to authenticate. A service ticket for the honey SPN means someone is kerberoasting. A TGT request without pre-authentication for the AS-REP honey means someone is AS-REP roasting. Any logon or authentication attempt with a lure account means someone found its credentials and tried them. Give every lure location its own honey account, and the account name tells you where the attacker found it.

This is the deception counterpart to I03 and I04. Those look for roasting **volume and weak encryption** across real accounts. This rule fires on **one** request for a single account that should never be touched.

## Prerequisite
- DCs: **Audit Kerberos Authentication Service** and **Audit Kerberos Service Ticket Operations** (Success and Failure), and **Audit Credential Validation** (Success and Failure). Member servers: **Audit Logon** (Success and Failure).
- Replace the placeholder names in the query with your honey accounts **in the deployed Elastic rule only**. Don't commit real names to this repo. See the README section on keeping the traps secret.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded* METADATA _id, _index, _version
| WHERE event.code IN ("4768", "4769", "4770", "4771", "4776", "4624", "4625", "4648")
| EVAL target = TO_LOWER(MV_FIRST(SPLIT(COALESCE(winlog.event_data.TargetUserName, ""), "@"))),
       service = TO_LOWER(COALESCE(winlog.event_data.ServiceName, "")),
       honey_account = CASE(event.code IN ("4769", "4770"), service, target)
// honey accounts, one per lure location (placeholders). sAMAccountName in lowercase: both sides are lowercased
| WHERE honey_account IN ("<honey_kerberoast>", "<honey_asrep>", "<honey_description>",
                          "<honey_sysvol>", "<honey_lsass>", "<honey_sharepoint>", "<honey_confluence>")
| EVAL trap = CASE(
         event.code IN ("4769", "4770"), "kerberoast: service ticket for honey SPN",
         event.code == "4768" AND winlog.event_data.PreAuthType == "0", "as-rep roast: TGT without pre-auth",
         event.code == "4648", "explicit credential use (runas or tool)",
         "authentication or logon attempt"),
       requester = CASE(event.code IN ("4769", "4770"), TO_LOWER(COALESCE(winlog.event_data.TargetUserName, "")),
                        event.code == "4648", TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, "")), ""),
       from_ip = COALESCE(TO_STRING(source.ip), winlog.event_data.IpAddress),
       from_host = COALESCE(winlog.event_data.WorkstationName, winlog.event_data.Workstation, ""),
       result = COALESCE(winlog.event_data.Status, winlog.event_data.FailureReason, event.outcome)
| KEEP @timestamp, honey_account, trap, requester, from_ip, from_host, result, event.code,
       winlog.event_data.TicketEncryptionType, winlog.event_data.LogonType, winlog.computer_name, _id, _version, _index
```

**Reading `trap` and `honey_account` together:**
- `<honey_kerberoast>` with "kerberoast": someone requested its service ticket. `requester` is the account that did it, and `from_ip` is where it came from.
- `<honey_description>` with "authentication or logon attempt": someone read the description-field bait and tried it. That means they enumerated AD user attributes (W09 for the collector tool, or B04's LDAP tiers, may show the enumeration itself).
- `<honey_lsass>` used anywhere: someone dumped LSASS on one of the servers holding the injected credentials.

## Suppression
Suppress by `honey_account`, `trap` for 1h. Alerts missing a key field are not suppressed. One roasting run or spray produces a burst of events. A different trap firing, or the same trap an hour later, alerts again.

## Known false positives / exclusions
- **Your own audit tooling** (PingCastle, Purple Knight, BloodHound collection by the security team, kerberoast audit scripts). Agree a schedule and exclude the tool account and host by `requester` and `from_ip`, or simply expect the alert and close it.
- **Vulnerability scanners with Kerberos checks.** Exclude the scanner's IP.
- Nothing else should touch these accounts. If something does, find out what before excluding it.

## Triage
- Treat as a confirmed intrusion or red-team action. Identify `from_ip` and `requester`, contain the source host with Falcon, and check the requester account for compromise (I06, X02).
- Map the honey account back to its lure location using the restricted deception register. That tells you what the attacker read (SYSVOL, SharePoint, Confluence, LSASS memory on a specific server) and lets you reconstruct their path.

## Test
From a lab domain-joined host:
- **Kerberoast trap:** `Rubeus.exe kerberoast /user:<honey_kerberoast> /nowrap`, or Impacket `GetUserSPNs.py -request-user <honey_kerberoast>`.
- **AS-REP trap:** `Rubeus.exe asreproast /user:<honey_asrep>`.
- **Credential lures:** `runas /user:CORP\<honey_description> cmd` with the bait password (fails with 4771 or 4625).
