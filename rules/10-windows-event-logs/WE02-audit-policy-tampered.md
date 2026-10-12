---
id: WE02
name: Audit logging removed from a monitored subcategory, or per-user audit policy set
category: windows-events
status: todo
severity: high
language: esql
index: logs-system.security*, logs-windows.forwarded*
mitre: [T1685.001]
data_source: Windows Security events 4719 (system audit policy changed) and 4912 (per-user audit policy changed)
suppression:
  fields: [host_key]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Attackers switch off the audit subcategories that would record them (`auditpol /set ... /success:disable`, `auditpol /clear`), or exempt one account from auditing with a per-user policy. Event 4719 records each subcategory change, and its `AuditPolicyChanges` codes say whether success or failure auditing was removed. Removing auditing from a subcategory this library depends on is rare outside a planned Group Policy change. Per-user audit policy (4912) is almost never used legitimately.

The 4719 subject is usually the machine account even when a person ran `auditpol`, so the rule does not filter on who made the change. It keys on what was removed instead. Adding auditing is ignored.

## Query
```esql
FROM logs-system.security*, logs-windows.forwarded* METADATA _id, _index, _version
| WHERE event.code IN ("4719", "4912")
| EVAL host_key = TO_LOWER(MV_FIRST(SPLIT(winlog.computer_name, "."))),
       changes = MV_CONCAT(TO_STRING(winlog.event_data.AuditPolicyChanges), ","),   // raw codes, e.g. "%%8448, %%8451"
       subcat = TO_LOWER(COALESCE(winlog.event_data.SubCategory, winlog.event_data.SubcategoryGuid, "")),
       subject = TO_LOWER(COALESCE(winlog.event_data.SubjectUserName, ""))
// %%8448 = success removed, %%8450 = failure removed
| WHERE event.code == "4912"
   OR ((changes LIKE "*%%8448*" OR changes LIKE "*%%8450*")
       AND subcat IN ("logon", "special logon", "process creation", "user account management",
                      "security group management", "computer account management", "directory service access",
                      "directory service changes", "audit policy change", "authentication policy change",
                      "sensitive privilege use", "credential validation", "kerberos authentication service",
                      "kerberos service ticket operations", "security system extension", "detailed file share",
                      "other object access events", "certification services"))
| KEEP @timestamp, host_key, winlog.computer_name, event.code, subcat, changes,
       winlog.event_data.AuditPolicyChangesDescription, subject, winlog.event_data.TargetUserSid, _id, _version, _index
```
`SubCategory` is the name the integration derives from `SubcategoryGuid`. In `%%8448`, `%` is a literal character, not a wildcard; ES|QL `LIKE` uses only `*` and `?`.

## Suppression
Suppress by `host_key` for 1h. Alerts missing a key field are not suppressed. `auditpol /clear` writes one 4719 per subcategory.

## Known false positives / exclusions
- A planned Group Policy change that lowers an audit setting. It shows as the same removal on many hosts at once; confirm against change control.
- Conflicting legacy and advanced audit policy in Group Policy can flip settings on every refresh. That repeats on a schedule; fix the policy rather than excluding it.

## Triage
- Read `AuditPolicyChangesDescription` and `subcat` for what was switched off, re-apply the policy (`gpupdate /force`), and look for the process that ran `auditpol` on the host (FDR or 4688) to find the actor.
- For 4912, `TargetUserSid` is the account exempted from or added to auditing. Remove the per-user policy and investigate that account.

## Test
On a lab host, disable success auditing for the Logon subcategory with `auditpol`, then revert.
