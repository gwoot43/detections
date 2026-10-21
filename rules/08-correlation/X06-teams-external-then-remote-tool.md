---
id: X06
name: External Teams contact followed by remote-access tool on the same user's host
category: correlation
status: todo
language: esql
index: logs-o365.audit-*, logs-yourorg-crowdstrike-data-default*
mitre: [T1566, T1219, T1204]
data_source: Microsoft 365 audit (Teams chat created from another tenant) + CrowdStrike FDR (W10 tool list) joined on the user
suppression:
  fields: [usr]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
The help-desk social engineering chain: someone in an external tenant opens a Teams chat or call, then the user is talked into running Quick Assist or another remote tool. Either half is individually plausible. A new chat from an outside tenant followed within two hours by a remote-access tool starting on that user's host is the Black Basta and 3AM initial-access pattern.

## Prerequisite
- `o365.audit.ParticipantInfo.HasForeignTenantUsers` is not in the O365 integration's field list. It's mapped from the data, so the query fails with "Unknown column" until the first Teams event with `ParticipantInfo` is indexed. Check with `FROM logs-o365.audit-* | WHERE event.action == "ChatCreated" | KEEP o365.audit.ParticipantInfo.*`.
- FDR process events carry `user.name` only when the CrowdStrike integration's "Enrich Host and User Metadata" option (userinfo) is on. It arrives as `DOMAIN\user`.
- The join compares the UPN prefix of the chat member with the Falcon account name. If your UPN prefix differs from the sAMAccountName, this rule cannot pair them.

## Query
```esql
FROM logs-o365.audit-*, logs-yourorg-crowdstrike-data-default*
| WHERE @timestamp > NOW() - 2 hours
| EVAL pname = TO_LOWER(process.name),
       foreign = TO_LOWER(TO_STRING(o365.audit.ParticipantInfo.HasForeignTenantUsers)),
       creator = TO_LOWER(COALESCE(user.email, ""))
// contact: a new Teams chat that includes another tenant, started by someone outside your domains
//          (placeholders: list your own domains and any sanctioned support vendor's domain)
| EVAL contact = event.provider == "MicrosoftTeams" AND event.action == "ChatCreated" AND foreign == "true"
         AND NOT TO_LOWER(COALESCE(user.domain, "")) IN ("<your_domain>", "<your_tenant>.onmicrosoft.com", "<sanctioned_vendor_domain>"),
       tool = event.action == "processrollup2" AND host.os.type == "windows"
         AND pname IN ("quickassist.exe", "anydesk.exe", "teamviewer.exe", "teamviewerqs.exe", "screenconnect.windowsclient.exe",
                       "rustdesk.exe", "logmein.exe", "supremo.exe", "zohoassist.exe")
| WHERE contact OR tool
// the internal user: on a chat, each member UPN except the external creator; on the endpoint, the Falcon user
| MV_EXPAND related.user
| EVAL who = CASE(contact, related.user, user.name)
| WHERE tool OR (who LIKE "*@*" AND TO_LOWER(who) != creator)
| EVAL usr = TO_LOWER(MV_FIRST(SPLIT(MV_LAST(SPLIT(who, "\\")), "@"))),
       contact_ts = CASE(contact, @timestamp, NULL),
       tool_ts = CASE(tool, @timestamp, NULL),
       external_sender = CASE(contact, creator, NULL),
       tool_name = CASE(tool, pname, NULL),
       tool_host = CASE(tool, host.name, NULL),
       tool_cmd = CASE(tool, process.command_line, NULL)
| WHERE usr IS NOT NULL AND usr != ""
| STATS first_contact = MIN(contact_ts), last_tool = MAX(tool_ts),
        external_senders = VALUES(external_sender), tools = VALUES(tool_name), hosts = VALUES(tool_host), command_lines = VALUES(tool_cmd)
    BY usr
| WHERE first_contact IS NOT NULL AND last_tool IS NOT NULL AND last_tool >= first_contact
| EVAL minutes_contact_to_tool = DATE_DIFF("minute", first_contact, last_tool)
| KEEP usr, first_contact, last_tool, minutes_contact_to_tool, external_senders, tools, hosts, command_lines
```

No LogScale version: the rule fires only when a remote tool follows a Teams chat from another tenant, and Microsoft 365 audit data isn't in Falcon; the FDR half on its own is W10.

Run every 15 minutes. The 2-hour lookback is the correlation window: the tool must start after the chat was created.

How the user is found: when someone in another tenant starts the chat, the audit event's `user.*` is that outsider, and your user only appears as a chat member. The integration copies every member UPN into `related.user`, so the query expands that list and keeps the UPNs other than the creator's. This overlaps W10 on the endpoint side; the correlation raises its confidence.

## Suppression
Suppress by `usr` for 24h. Alerts missing a key field are not suppressed. Correlation rule; suppression stops repeated matches for the same session.

## Known false positives / exclusions
- Legitimate external support that uses Teams and a remote tool. Add the vendor's domain to the `user.domain` list, and remove your own approved RMM from the process list (it is covered by W10 exclusions).
- A chat your user starts with a partner, then a remote session for a meeting. The creator filter drops chats started from your own domains.

## Triage
- Call the user. If they were contacted out of the blue and guided to install or run the tool, isolate the host, kill the session, and treat as active intrusion. Review what the remote operator did.

## Test
From a lab external tenant, start a Teams chat with a lab user, then launch Quick Assist on their host within the hour.
