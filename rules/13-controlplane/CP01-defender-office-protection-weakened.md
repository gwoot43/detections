---
id: CP01
name: Defender for Office 365 protection rule or policy disabled, deleted or switched off, including zero-hour auto purge (ZAP)
category: controlplane
status: todo
severity: high
language: esql
index: logs-o365.audit-*
mitre: [T1685, T1550]
data_source: Microsoft 365 Unified Audit Log (Exchange admin)
suppression:
  fields: [usr, event.action]
  duration: 6h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Safe Links, Safe Attachments, anti-phishing, anti-malware and anti-spam are the controls that stop mail-borne attacks. Disabling or deleting one of their rules or policies, or switching a policy off, lets the next phishing wave through, and it is sometimes done deliberately before one. These are rare administrator actions by a small team, each recorded as a distinct Exchange cmdlet. Routine `Set-*` edits are kept only when a parameter switches protection off.

That includes zero-hour auto purge (ZAP), which removes mail re-rated malicious after delivery. Turning it off in the anti-malware or anti-spam policy means a message found bad after delivery stays in the inbox. It is a deliberate weakening of post-delivery protection and a rare admin change.

## Prerequisite
`o365.audit.Parameters.Enabled` is mapped by the integration. These parameters, all under `o365.audit.Parameters.`, are mapped only after the first event that sets them: `EnableSafeLinksForEmail`, `AllowClickThrough`, `Enable`, `EnableATPForSPOTeamsODB`, and the ZAP switches `ZapEnabled` (anti-malware, and the older anti-spam switch), `PhishZapEnabled` and `SpamZapEnabled` (anti-spam). On most tenants the ZAP switches do not exist yet. If one is missing, the query fails with "Unknown column". Map them as `keyword` in the `logs-o365.audit@custom` component template.

## Query
```esql
FROM logs-o365.audit-* METADATA _id, _index, _version
| WHERE event.provider == "Exchange" AND event.outcome == "success"
  AND event.action IN (
    "Disable-SafeLinksRule", "Remove-SafeLinksRule", "Remove-SafeLinksPolicy", "Set-SafeLinksPolicy",
    "Disable-SafeAttachmentRule", "Remove-SafeAttachmentRule", "Remove-SafeAttachmentPolicy", "Set-SafeAttachmentPolicy",
    "Disable-AntiPhishRule", "Remove-AntiPhishRule", "Remove-AntiPhishPolicy", "Set-AntiPhishPolicy",
    "Disable-MalwareFilterRule", "Remove-MalwareFilterRule", "Remove-MalwareFilterPolicy", "Set-MalwareFilterPolicy", "New-MalwareFilterPolicy",
    "Disable-HostedContentFilterRule", "Remove-HostedContentFilterRule", "Remove-HostedContentFilterPolicy", "Set-HostedContentFilterPolicy", "New-HostedContentFilterPolicy",
    "Disable-ATPProtectionPolicyRule", "Disable-EOPProtectionPolicyRule",
    "Set-AtpPolicyForO365")
| EVAL usr = TO_LOWER(o365.audit.UserId),
       enabled = TO_LOWER(COALESCE(o365.audit.Parameters.Enabled, "")),
       safelinks_email = TO_LOWER(COALESCE(o365.audit.Parameters.EnableSafeLinksForEmail, "")),
       click_through = TO_LOWER(COALESCE(o365.audit.Parameters.AllowClickThrough, "")),
       safeattach = TO_LOWER(COALESCE(o365.audit.Parameters.Enable, "")),
       atp_spo = TO_LOWER(COALESCE(o365.audit.Parameters.EnableATPForSPOTeamsODB, "")),
       zap = TO_LOWER(COALESCE(o365.audit.Parameters.ZapEnabled, "")),
       phish_zap = TO_LOWER(COALESCE(o365.audit.Parameters.PhishZapEnabled, "")),
       spam_zap = TO_LOWER(COALESCE(o365.audit.Parameters.SpamZapEnabled, ""))
// Disable-/Remove- weaken on their own; Set-* and New-* only when a switch is turned off
| EVAL change = CASE(
         event.action LIKE "Disable-*" OR event.action LIKE "Remove-*", "disabled or removed",
         zap == "false" OR phish_zap == "false" OR spam_zap == "false", "zap disabled",
         enabled == "false", "policy switched off",
         safelinks_email == "false", "safe links for email off",
         click_through == "true", "safe links click-through allowed",
         safeattach == "false", "safe attachments off",
         atp_spo == "false", "safe attachments for sharepoint, onedrive and teams off",
         NULL)
| WHERE change IS NOT NULL
| WHERE NOT usr IN ("svc-exo-policy-pipeline@yourdomain.com")   // policy-as-code account, if any
| KEEP @timestamp, usr, event.action, change, o365.audit.ObjectId, source.ip, zap, phish_zap, spam_zap, _id, _version, _index
```
ZAP is read from the anti-malware (`ZapEnabled`) and anti-spam (`PhishZapEnabled`, `SpamZapEnabled`, and the older `ZapEnabled`) policies; `zap`, `phish_zap` and `spam_zap` show which switch was turned off. Anti-phishing and Safe Links policies have no ZAP switch. Allow-list entries are CP03.

## Suppression
Suppress by `usr`, `event.action` for 6h. Alerts missing a key field are not suppressed. One policy edit can write several lines; a different admin or action still alerts.

## Known false positives / exclusions
- Policy-as-code pipelines and the Defender team's planned work. Keep the pipeline account in the inline exclusion and confirm human changes against change control. There is almost no good reason to disable ZAP in production.
- Removing a custom policy while moving users to the preset security policies. Ticket-gated.

## Triage
- Read the change. A Safe Links or Safe Attachments rule disabled, or click-through allowed, is a control being removed. Revert it, check whether a phishing wave followed (E01, E02, E13), and who made the change (correlate with a privileged role add, C03).
- `zap disabled`: re-enable ZAP, confirm who changed it, and check for delivered-but-malicious mail in the window it was off (E14).

## Test
Disable a test Safe Links rule in a lab tenant and re-enable it. Disable ZAP on a test anti-spam policy and re-enable it.
