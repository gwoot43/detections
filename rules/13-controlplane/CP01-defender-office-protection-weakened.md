---
id: CP01
name: Defender for Office 365 protection policy weakened or deleted
category: controlplane
status: todo
severity: high
language: esql
index: logs-o365.audit-*
mitre: [T1562.001, T1562.006, T1550]
data_source: Microsoft 365 Unified Audit Log (Exchange admin / Security and Compliance Center)
suppression:
  fields: [usr, event.action]
  duration: 6h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Safe Links, Safe Attachments and anti-phishing are the Defender for Office 365 controls that stop mail-borne attacks. Disabling a rule, deleting a policy, or weakening an anti-phish policy lets the next phishing wave through, and it is sometimes done deliberately before one. These are rare administrator actions by a small team, each recorded as a distinct Exchange cmdlet in the audit log.

## Query
```esql
FROM logs-o365.audit-* METADATA _id, _index, _version
| WHERE event.dataset == "o365.audit" AND event.provider == "Exchange" AND event.outcome == "success"
  AND event.action IN (
    "Disable-SafeLinksRule", "Remove-SafeLinksRule", "Set-SafeLinksPolicy", "Set-SafeLinksRule",
    "Disable-SafeAttachmentRule", "Remove-SafeAttachmentRule", "Set-SafeAttachmentPolicy", "Set-SafeAttachmentRule",
    "Disable-AntiPhishRule", "Remove-AntiPhishRule", "Set-AntiPhishPolicy", "Remove-AntiPhishPolicy",
    "Set-AtpPolicyForO365",
    "Set-MalwareFilterPolicy", "Remove-MalwareFilterRule", "Disable-MalwareFilterRule",
    "Set-HostedContentFilterPolicy", "Disable-HostedContentFilterRule"
  )
| EVAL usr = TO_LOWER(o365.audit.UserId), params = TO_LOWER(TO_STRING(o365.audit.Parameters))
// weakening signals in the parameters of a Set-*; Disable-/Remove- are weakening on their own
| EVAL weakening = event.action LIKE "Disable-*" OR event.action LIKE "Remove-*"
                   OR params LIKE "*enabled*false*" OR params LIKE "*\"false\"*"
                   OR params LIKE "*bypass*" OR params LIKE "*off*" OR params LIKE "*allow*"
                   OR params LIKE "*action*\":\"*none*" OR params LIKE "*scanurls*false*" OR params LIKE "*deliverymessageafterscan*false*"
| WHERE weakening
| WHERE NOT (usr IN ("svc-exo-policy-pipeline@yourdomain.com"))   // your policy-as-code account, if any
| KEEP @timestamp, usr, event.action, o365.audit.ObjectId, o365.audit.ClientIP, params
```
Set-* cmdlets are kept only when the parameters show a weakening change, so routine tightening does not fire. Confirm the `Parameters` shape in your integration; if it is a structured array, test the specific fields instead of the string.

## Suppression
Suppress by `usr`, `event.action` for 6h. Alerts missing a key field are not suppressed. One policy edit can write several lines; a different admin or action still alerts.

## Known false positives / exclusions
- Policy-as-code pipelines and the Defender team's planned work. Exclude the pipeline account inline and confirm human changes against change control.
- Preset security policies being reconfigured during a migration. Ticket-gated.

## Triage
- Read the change. A Safe Links or Safe Attachments rule disabled, or an anti-phish policy with its action set to none or a domain allow-listed, is a control being removed. Revert it and check whether a phishing wave followed (E01, E02) and who made the change (correlate with a privileged role add, C03).

## Test
Disable a test Safe Links rule in a lab tenant and re-enable it.
