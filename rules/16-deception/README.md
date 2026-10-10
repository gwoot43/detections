# Deception: setup guide and detections

Deception plants things nobody legitimate has a reason to touch: honey accounts, decoy files, decoy host names. Any interaction is close to a guaranteed true positive, so these are the highest-confidence alerts in the library. They are especially good against a red team, because they catch reconnaissance and credential hunting that look like normal admin activity to every other rule.

Everything here is free: native AD and Entra objects, the M365 audit log you already ingest, Falcon telemetry you already have, and open-source OpenCanary and Canarytokens.

## The rules

| Rule | Trap | Fires on |
|---|---|---|
| D01 | Honey AD accounts (kerberoast SPN, AS-REP, description bait, lure credentials) | Any Kerberos, NTLM or logon event naming a honey account |
| D02 | Honey Entra users and a honey service principal | Any sign-in attempt, any result, any category |
| D03 | Decoy SharePoint/OneDrive file, decoy Confluence page | Opened, previewed, downloaded or copied |
| D04 | Decoy host and DNS names (OpenCanary) | Name looked up or IP connected to from any Falcon host, or any OpenCanary hit |

Every rule is **critical severity** and should be tagged `deception`. Fire them as direct alerts. Don't make them only risk contributions in a risk-based alerting model: they shouldn't wait for a score to build up. You can also emit a high-weight risk event for RBA and UEBA later.

## Keep the traps secret

A deception that the red team can read about is worthless.
- **The rules in this repo use placeholders** (`<honey_kerberoast>`, `<decoy_file_1.xlsx>`). Put the real values only in the deployed Elastic rules. Never commit them here, and never put them in tickets, Confluence or chat.
- Keep a **restricted deception register** (an access-controlled spreadsheet or vault entry) listing each asset: what it is, where it's placed, which honey identity it carries, which rule watches it, and an owner. Without it, an alert names a honey account but nobody can say where it was planted.
- Put the deployed rules in a **Kibana space or role** the red team and general IT can't read.
- Brief only the **white cell** (IR lead, CISO, the engagement lead) plus the few AD, M365 and DNS admins who create the objects.
- Make the assets look real. Follow your actual naming conventions. Never use "honey", "canary", "decoy" or "test" in a name, description or path.

## Phase 0: prepare (1-2 days)

1. Get sign-off from the IR lead or CISO, and agree who gets paged.
2. Create the deception register.
3. Confirm the log sources:

| Source | Needed for | Check |
|---|---|---|
| DC Security log: 4768, 4769, 4771, 4776 (Success and Failure) | D01 | Audit Kerberos Authentication Service, Kerberos Service Ticket Operations, Credential Validation |
| Member server Security log: 4624, 4625, 4648 | D01 | Audit Logon |
| Entra sign-in logs incl. **ServicePrincipalSignInLogs** | D02 | Diagnostic setting streams all three sign-in categories |
| M365 unified audit log | D03 | Already ingested for IN rules |
| Confluence Data Center access log | D03 option B | Only on Data Center; needs a custom log input |
| CrowdStrike FDR DnsRequest and NetworkConnectIP4 | D04 | Already ingested |

## Phase 1: identity traps (days 1-3)

Create three or four honey accounts in an OU where real service accounts live. Use **one account per lure location**, so the account name tells you where it was found.

**All honey accounts**
- **Password:** long and random (30+ characters), stored nowhere. Even if an attacker gets a hash, they can't crack it.
- **No real rights:** no real group memberships. To look attractive, add the account to an empty group with an admin-sounding name that grants nothing, and set a plausible description.
- **Deny logon rights:** a GPO denying the honey accounts interactive, Remote Desktop, batch and service logon. Attempts still produce the 4625 and 4771 events D01 needs, so the alerting is unaffected.
- **Entra:** let them sync if your other service accounts sync. A synced honey UPN gives D02 a second chance to catch the attempt. Give it no licence.

**Kerberoast trap (D01)**
```powershell
New-ADUser -Name "svc_sqlbak" -SamAccountName "svc_sqlbak" -Path "OU=Service Accounts,DC=corp,DC=local" `
  -AccountPassword (Read-Host -AsSecureString) -Enabled $true -Description "SQL backup agent - do not disable"
Set-ADUser svc_sqlbak -ServicePrincipalNames @{Add="MSSQLSvc/sqlbak01.corp.local:1433"}
```
Keep this account **enabled**. Common enumeration tools skip disabled accounts, so a disabled honey account would never be found. Point `sqlbak01` at the decoy host (Phase 3) so the SPN resolves.

**AS-REP trap (D01)**
```powershell
Set-ADAccountControl -Identity "<honey_asrep>" -DoesNotRequirePreAuth $true
```
Don't put a logon-hours restriction on this account. The KDC refuses requests outside logon hours, so the trap would answer with an error instead of looking real.

**Description bait (D01)**: put a **fake** password in the description of another honey account, for example `Temp password: Spring2023!`. It must not be the account's real password. Any logon attempt with it fails and shows up in D01. If your PAM or IAM tools flag passwords in description fields, tell their owners.

**Honey service principal (D02)**: an app registration with a plausible name (for example `Backup-Automation-Prod`), a client secret, and no API permissions. Plant the app ID, tenant ID and secret where a credential hunter would look: a decoy config file in an internal repo, a pipeline variable group, or a Key Vault secret named like a real one.

## Phase 2: credential lures (days 3-5)

Each lure carries a **different** honey account (or token).

| Lure | Placement | What fires |
|---|---|---|
| SharePoint workbook | "IT Ops - break glass accounts.xlsx" on a broadly readable site | D03 on open; D01 or D02 on credential use |
| Confluence page | A page in an infrastructure space, for example "VPN service accounts" | D03 option B (Data Center); D01 or D02 on credential use |
| NETLOGON or SYSVOL script | An old-looking logon script containing a mapped-drive line with honey credentials | D01 on credential use |
| Canarytokens | AWS API key token in `~/.aws/credentials` on jump hosts; a token in a decoy repo | Canarytokens' own alert (email or webhook) |

Notes:
- **Credential tokens beat document tokens in cloud storage.** Word and PDF tokens in SharePoint can fire on Microsoft's background scanning and previews, or stay silent when the file opens in the browser. D03's native audit approach avoids both problems.
- **Self-host Canarytokens** if you can (the project is open source and runs in Docker). Hosted tokens call back to `canarytokens.org`, which experienced red teams recognise. Send token alerts to a webhook your SOC watches. If you want them in Elastic, point the webhook at an Elastic Agent HTTP Endpoint input.
- **SharePoint noise:** run D03 in preview for a week after placing the file, and exclude any crawler, backup, DLP or Copilot service identity that touches it.

## Phase 3: network decoys (week 2, optional)

1. Build a small VM in the server VLAN with **OpenCanary** (SMB, RDP, SSH and HTTP modules). Don't put production data or real credentials on it.
2. Create DNS A records with tempting names (`pam01`, `vault-prod`, `sqlbak01`) pointing at it.
3. Ship `/var/tmp/opencanary.log` to Elastic with a Custom Logs integration (D04 option B).
4. D04 option A fires on any Falcon-managed host **resolving** those names, even if it never connects.
5. Agree exclusions with the vulnerability-scanning and monitoring teams, because they sweep every IP.

## Phase 4: detection and response

- Deploy D01-D04 at critical severity, tagged `deception`, with the real values in place.
- Runbook for any deception alert:
  1. Identify the source host and user from the alert.
  2. Contain the host with Falcon network containment.
  3. Look up the asset in the deception register to see where it was planted. That tells you what the attacker read and how far their reconnaissance got.
  4. Hunt backwards from the source host for the initial access, and forwards for other traps or real credentials used.
  5. During a red-team engagement, contact the white cell before containing, so you don't break the exercise unintentionally (unless the agreed rules say to contain).

## Phase 5: validate before the engagement

Fire every trap from a lab host and confirm the alert lands with acceptable latency. Each rule's **Test** section gives the exact steps. Then:
- **Tune out your own tooling:** security posture tools such as PingCastle, scheduled vulnerability scans, and asset discovery.
- **Review placements every quarter** so the lures stay plausible. Update dates in file names and descriptions, and keep the decoy pages looking recently edited.

## Entra identity detections reviewed alongside this work

These Entra ideas came up with the deception plan. This is how they map to the library:

| Idea | Status |
|---|---|
| Any sign-in by a honey user or honey service principal | **D02** (new) |
| Many different users signing in from one Entra device | **S22** (new) |
| Refresh-token (non-interactive) sign-in from a network the user has never used interactively | **S23** (new) |
| Same session ID from multiple ASNs or countries (AiTM token replay) | Already covered: S08 |
| Device code flow and ROPC | Already covered: S02, C11 |
| Developer tools (Azure CLI, Graph PowerShell, VS Code) used by non-developers | Already covered: S04 |
| Distributed low-and-slow spray | Already covered: S15 |
| MFA fatigue | Already covered: S12 |
| New MFA method after a risky or new-network sign-in | Already covered: I10, S11 |
| Conditional Access policy or named location changed | Already covered: C02 |
| Federation or domain authentication changed | Already covered: C01 |
| App credential added, consent granted, Global Admin or PIM role assigned | Already covered: C04, C05, C03 |
| User added as app owner, guest invited | Not built. The owner change is covered downstream when a credential is added (C04). Guest invitations are too noisy to page on. |
