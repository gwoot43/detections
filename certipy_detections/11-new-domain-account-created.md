---
id: ACCOUNTS-01
name: New domain user account - created outside the provisioning accounts, put straight into a privileged group, or named like a computer ($)
language: esql
index: logs-yourorg-microsoft-windows*
mitre: [T1136.002, T1098.007]
data_source: Windows Security 4720, 4728, 4732 and 4756 on the domain controllers
suppression:
  fields: [account_sid, finding]
  duration: 24h
  missing_fields: do_not_suppress
---
Accounts get created every day by whatever does your joiners (an identity-management service account, the helpdesk), so creation on its own is noise. An attacker's account looks different in one of three ways:
- **created by someone else:** an admin account or a compromised user creating it by hand (`net user /add /domain`, `New-ADUser`, Impacket's `addcomputer`-style tools, a C2 module), not your provisioning accounts;
- **made privileged straight away:** added to Domain Admins, Administrators or another privileged group within a day of being created;
- **named like a computer:** a user account ending in `$`, which hides among computer accounts in most listings. Real computer accounts are created with a different event (4741), so a user account (4720) ending in `$` is almost always deliberate.

Run hourly over the last 24 hours, so a group add the day after creation still pairs with it.
```esql
FROM logs-yourorg-microsoft-windows*
// Filter for user accounts created, and members added to security groups (global, local, universal)
| WHERE event.code IN ("4720", "4728", "4732", "4756")
// The account's SID (TargetSid on creation, MemberSid on a group add), and the group for adds
| EVAL account_sid = CASE(event.code == "4720", winevt.event_data.target_sid, winevt.event_data.member_sid),
       group = CASE(event.code != "4720", TO_LOWER(winevt.event_data.target_user_name), null),
       actor = TO_LOWER(winevt.event_data.subject_user_name)
// Group by account: when and by whom it was created, and what it was added to
| STATS created = MIN(@timestamp) WHERE event.code == "4720",
        account = VALUES(winevt.event_data.target_user_name) WHERE event.code == "4720",
        creator = VALUES(actor) WHERE event.code == "4720",
        unexpected_creator = COUNT(*) WHERE event.code == "4720"
          AND NOT actor IN ("<provisioning_account>", "<helpdesk_account>"),
        computer_style_name = COUNT(*) WHERE event.code == "4720" AND ENDS_WITH(winevt.event_data.target_user_name, "$"),
        privileged_adds = COUNT(*) WHERE group IN ("domain admins", "enterprise admins", "schema admins",
          "administrators", "account operators", "backup operators", "server operators", "print operators",
          "group policy creator owners", "dnsadmins", "key admins", "enterprise key admins"),
        groups = VALUES(group), added_by = VALUES(actor) WHERE event.code != "4720", dc = VALUES(host.name)
    BY account_sid
// Only accounts created in the window, labelled by the strongest reason
| WHERE created IS NOT NULL
| EVAL finding = CASE(privileged_adds > 0, "new_account_made_privileged",
                      computer_style_name > 0, "user_account_named_like_computer",
                      unexpected_creator > 0, "created_outside_provisioning",
                      NULL)
| WHERE finding IS NOT NULL
```
No LogScale version: the DCs' logs are in Elastic. Suppress by account and finding for 24h, so an account first flagged for its creator still alerts again when it's made privileged.

## Before turning it on
- Find who creates accounts today, and put the provisioning accounts in the list (lower case):
  ```esql
  FROM logs-yourorg-microsoft-windows*
  | WHERE event.code == "4720"
  | STATS accounts_created = COUNT(*), last_created = MAX(@timestamp) BY creator = TO_LOWER(winevt.event_data.subject_user_name)
  | SORT accounts_created DESC
  ```
  Run it over 90 days. The handful at the top are your joiner processes; anything that created one or two accounts is worth a look on its own.
- Check the field names (`target_sid`, `member_sid`, `target_user_name`, `subject_user_name`) against a 4720 and a 4728 in Discover.
- Add any other groups that are privileged in your domain (Tier-0 groups, groups with rights over the domain or the CA) to the list.

## What it misses
- An account created through a provisioning account the attacker controls: it looks like a joiner. The privileged-group finding still fires if it's made an admin.
- An existing, dormant account brought back into use instead of a new one (reset and re-enabled): 4722 and 4724, not 4720.
- Computer accounts (4741). AD05 covers those created by a standard user.
- Accounts created in Entra ID or a cloud directory rather than on-premises AD.

## When it fires
Ask the creator (or their manager) whether it was intended. If not: disable the new account, then look at the creator's own logons around `created` (4624 on the DCs, from which address) and treat the creator as compromised. For `new_account_made_privileged`, check what the account did since (4624 and 4769 by it) and who added it (`added_by`). For a `$` user account, look for its logons: an attacker's hidden account gets used.
