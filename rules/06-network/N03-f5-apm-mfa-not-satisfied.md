---
id: N03
name: F5 APM session established without expected MFA step
category: network
status: todo
severity: medium
language: esql
index: logs-f5.apm-*
mitre: [T1133, T1078, T1556]
data_source: F5 APM access policy / VPE logs
---
## Why this is high fidelity
If your APM access policy enforces MFA, every allowed session should show the MFA agent step succeeding. A session that reaches "allow" without the MFA policy item, or where the MFA step is skipped by a fallback branch, is a policy gap or an attacker who found the branch that bypasses it.

## Query
```esql
FROM logs-f5.apm-*
| WHERE TO_LOWER(COALESCE(f5.apm.result, "")) IN ("allow", "successful", "success") OR event.outcome == "success"
| EVAL agent = TO_LOWER(TO_STRING(COALESCE(f5.apm.agent, f5.apm.policy_result, message)))
// your MFA policy item name as it appears in the APM log (e.g. "ad_auth_then_radius", "duo", "logon_mfa")
| WHERE NOT (agent LIKE "*mfa*" OR agent LIKE "*duo*" OR agent LIKE "*radius*" OR agent LIKE "*totp*" OR agent LIKE "*second factor*")
| KEEP @timestamp, user.name, source.ip, agent, message
```
This rule is only as good as your APM logging verbosity. Turn on per-session-variable or VPE logging so the MFA step is visible, then match on the real item name. If you cannot see the step, alert instead on any allowed session whose access policy name is not the MFA-enforcing policy.

## Known false positives / exclusions
- Service or machine-tunnel accounts exempt from MFA by design. Exclude those accounts explicitly.

## Triage
- If a real user session skipped MFA, find which VPE branch allowed it and close the gap. Check the session's source and internal activity.

## Test
Configure a test access policy branch that allows without MFA and connect through it.
