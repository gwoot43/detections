---
id: CERTIPY-02
name: User's UPN set to a bare name or a computer account's name (ESC9 / ESC10 set-up, certipy account update -upn)
language: esql
index: logs-yourorg-microsoft-windows*
mitre: [T1649, T1098]
data_source: Windows Security 4738 on the domain controllers
suppression:
  fields: [winevt.event_data.target_user_name]
  duration: 24h
  missing_fields: do_not_suppress
---
ESC9 and ESC10 need one trick: change a victim's UPN to the target's name, request a certificate as the victim, change it back, then log on with the certificate as the target. Certipy does it with `certipy account update -user <victim> -upn administrator`. AD won't allow two accounts the same UPN, so the attacker drops the domain (`administrator`) or borrows a computer account's name (`dc01$@corp.example`). Real UPNs always have `@domain`, and never a computer name.

Run every 15 minutes over the last 20.
```esql
FROM logs-yourorg-microsoft-windows* METADATA _id, _index, _version
// Filter for user accounts changed where the UPN was set (unchanged attributes are logged as "-")
| WHERE event.code == "4738" AND winevt.event_data.user_principal_name IS NOT NULL
  AND NOT winevt.event_data.user_principal_name IN ("-", "%%1793")
// Keep UPNs with no domain, or a computer account's name
| WHERE NOT winevt.event_data.user_principal_name LIKE "*@*" OR winevt.event_data.user_principal_name LIKE "*$@*"
// Display results
| KEEP @timestamp, host.name, winevt.event_data.target_user_name, winevt.event_data.user_principal_name,
       winevt.event_data.subject_user_name, _id, _index, _version
```
Suppress by the changed account for 24h.

## Before turning it on
- Check the field names against a 4738 in Discover; `user_principal_name`, `target_user_name` and `subject_user_name` are guesses at your pipeline's snake_case.
- Run it over 90 days. Any hit is worth a question; a service account created with a bare UPN years ago shows up only when it's changed.

## What it misses
- A UPN change on a computer account (4742), and the dNSHostName trick (Certifried): AD05.
- A UPN set to a real-looking `name@domain` that no one else uses. The attacker can't take the target's own UPN, so they rarely bother.

## When it fires
`subject_user_name` changed `target_user_name`. Expect the UPN to be changed back within minutes, and a certificate request as `target_user_name` on the CA in between (AD14, I09). Look for a certificate logon as the account the UPN named (AD15, AD16, AD17).
