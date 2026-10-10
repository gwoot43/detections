---
id: CP01
name: Defender for Office 365 protection rule or policy disabled, deleted or switched off
category: controlplane
status: todo
severity: high
language: esql
index: logs-o365.audit-*
mitre: [T1562.001, T1562.006, T1550]
data_source: Microsoft 365 Unified Audit Log (Exchange admin)
suppression:
  fields: [usr, event.action]
  duration: 6h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Safe Links, Safe Attachments, anti-phishing, anti-malware and anti-spam are the controls that stop mail-borne attacks. Disabling or deleting one of their rules or policies, or switching a policy off, lets the next phishing wave through, and it is sometimes done deliberately before one. These are rare administrator actions by a small team, each recorded as a distinct Exchange cmdlet. Routine `Set-*` edits are kept only when a parameter switches protection off.

## Prerequisite
`o365.audit.Parameters.Enabled` is mapped by the integration. `EnableSafeLinksForEmail`, `AllowClickThrough`, `Enable` and `EnableATPForSPOTeamsODB` (all under `o365.audit.Parameters.`) are mapped only after the first event that sets them. If one is missing, the query fails with "Unknown column". Map them as `keyword` in the `logs-o365.audit@custom` component template.

## Query
```esql
FROM logs-o365.audit-* METADATA _id, _index, _version
| WHERE event.provider == "Exchange" AND event.outcome == "success"
  AND event.action IN (
    "Disable-SafeLinksRule", "Remove-SafeLinksRule", "Remove-SafeLinksPolicy", "Set-SafeLinksPolicy",
    "Disable-SafeAttachmentRule", "Remove-SafeAttachmentRule", "Remove-SafeAttachmentPolicy", "Set-SafeAttachmentPolicy",
    "Disable-AntiPhishRule", "Remove-AntiPhishRule", "Remove-AntiPhishPolicy", "Set-AntiPhishPolicy",
    "Disable-MalwareFilterRule", "Remove-MalwareFilterRule", "Remove-MalwareFilterPolicy",
    "Disable-HostedContentFilterRule", "Remove-HostedContentFilterRule", "Remove-HostedContentFilterPolicy",
    "Disable-ATPProtectionPolicyRule", "Disable-EOPProtectionPolicyRule",
    "Set-AtpPolicyForO365")
| EVAL usr = TO_LOWER(o365.audit.UserId),
       enabled = TO_LOWER(COALESCE(o365.audit.Parameters.Enabled, "")),
       safelinks_email = TO_LOWER(COALESCE(o365.audit.Parameters.EnableSafeLinksForEmail, "")),
       click_through = TO_LOWER(COALESCE(o365.audit.Parameters.AllowClickThrough, "")),
       safeattach = TO_LOWER(COALESCE(o365.audit.Parameters.Enable, "")),
       atp_spo = TO_LOWER(COALESCE(o365.audit.Parameters.EnableATPForSPOTeamsODB, ""))
// Disable-/Remove- weaken on their own; Set-* only when a switch is turned off
| EVAL change = CASE(
         event.action LIKE "Disable-*" OR event.action LIKE "Remove-*", "disabled or removed",
         enabled == "false", "policy switched off",
         safelinks_email == "false", "safe links for email off",
         click_through == "true", "safe links click-through allowed",
         safeattach == "false", "safe attachments off",
         atp_spo == "false", "safe attachments for sharepoint, onedrive and teams off",
         NULL)
| WHERE change IS NOT NULL
| WHERE NOT usr IN ("svc-exo-policy-pipeline@yourdomain.com")   // policy-as-code account, if any
| KEEP @timestamp, usr, event.action, change, o365.audit.ObjectId, source.ip
```
ZAP switches in the anti-malware and anti-spam policies are E12. Allow-list entries are CP03.

## Suppression
Suppress by `usr`, `event.action` for 6h. Alerts missing a key field are not suppressed. One policy edit can write several lines; a different admin or action still alerts.

## Known false positives / exclusions
- Policy-as-code pipelines and the Defender team's planned work. Keep the pipeline account in the inline exclusion and confirm human changes against change control.
- Removing a custom policy while moving users to the preset security policies. Ticket-gated.

## Triage
- Read the change. A Safe Links or Safe Attachments rule disabled, or click-through allowed, is a control being removed. Revert it, check whether a phishing wave followed (E01, E02, E13), and who made the change (correlate with a privileged role add, C03).

## Test
Disable a test Safe Links rule in a lab tenant and re-enable it.
