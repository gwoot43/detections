---
id: AD05
name: Computer account changed to impersonate a domain controller, or created by a standard user
category: ad-attack
status: todo
severity: critical
rank: 5
language: esql
index: logs-windows.security-*
mitre: [T1078.002, T1068, T1136.002]
data_source: Windows Security events 4781, 4742 and 4741 from domain controllers
suppression:
  fields: [target, finding]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Several domain-takeover paths work by making a computer account look like a domain controller. Each leaves a distinct, rare change on a computer account:
- **sAMAccountName spoofing (noPac):** a computer account renamed so its name no longer ends in `$`, which lets it collide with a DC's name during ticket requests.
- **dNSHostName spoofing (Certifried):** a computer's DNS host name changed to something other than its own name, typically a DC's, to obtain a certificate for that DC.
- **Anonymous change to a computer account:** a computer account, typically a DC's, modified by `ANONYMOUS LOGON`, the trace of the Netlogon (ZeroLogon) flaw.
- **Computer account created by a standard user (medium):** the machine-account quota lets any user create computers. It is the usual first step for the attacks above and for resource-based delegation abuse (I14). IT joins machines with named provisioning or admin accounts.

Severity is critical for the first three and medium for the last.

## Query
```esql
FROM logs-windows.security-* METADATA _id, _index, _version
| WHERE event.code IN ("4781", "4742", "4741")
| EVAL actor = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, "")),
       old_name = TO_LOWER(COALESCE(winlog.event_data.OldTargetUserName, "")),
       new_name = TO_LOWER(COALESCE(winlog.event_data.NewTargetUserName, "")),
       target = TO_LOWER(COALESCE(winlog.event_data.TargetUserName, winlog.event_data.NewTargetUserName, "")),
       dns = TO_LOWER(COALESCE(winlog.event_data.DnsHostName, ""))
| EVAL base = CASE(ENDS_WITH(target, "$"), SUBSTRING(target, 1, LENGTH(target) - 1), target)
| EVAL samaccount_spoof = event.code == "4781" AND ENDS_WITH(old_name, "$") AND NOT ENDS_WITH(new_name, "$"),
       dnshostname_spoof = event.code == "4742" AND dns != "" AND dns != "-" AND NOT STARTS_WITH(dns, base),
       anonymous_change = event.code == "4742" AND actor == "anonymous logon",
       user_created_computer = event.code == "4741" AND NOT ENDS_WITH(actor, "$")
                               AND NOT (actor IN ("svc-domainjoin", "svc-autopilot"))   // your provisioning and IT join accounts
| WHERE samaccount_spoof OR dnshostname_spoof OR anonymous_change OR user_created_computer
| EVAL finding = CASE(samaccount_spoof, "samaccountname_spoofing",
                      dnshostname_spoof, "dnshostname_spoofing",
                      anonymous_change, "anonymous_computer_account_change",
                      "computer_created_by_user"),
       severity = CASE(user_created_computer AND NOT (samaccount_spoof OR dnshostname_spoof OR anonymous_change), "medium", "critical")
| KEEP @timestamp, host.name, actor, target, old_name, new_name, dns, finding, severity
```
The medium branch is only as clean as the provisioning list. If IT staff join machines with their personal admin accounts, add those accounts, or set the machine-account quota to 0 and delegate joining instead, which removes the attack path as well as the noise.

## Suppression
Suppress by `target`, `finding` for 1h. Alerts missing a key field are not suppressed. One change writes several events; a different computer or finding still alerts.

## Known false positives / exclusions
- A legitimate computer rename can change the DNS host name before the account name is updated. The `STARTS_WITH` check against the account's own name removes most of these.
- Help-desk staff joining machines with personal accounts, for the medium branch. Fix the process or list the accounts.

## Triage
- **Critical findings:** treat as an attempted domain takeover. Revert the name or DNS host name, disable the computer account, check whether a ticket or certificate was issued for a DC name right after (I09, AD08), and confirm DCs are fully patched.
- **Computer created by a user:** confirm with the user. An unexplained computer account is usually staging for a later step; check it for delegation (I14) or shadow credentials (I12).

## Test
In a lab, create a computer account as a standard user (medium branch), then rename it to drop the `$` (critical branch).
