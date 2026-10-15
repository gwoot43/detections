---
id: B08
name: Credential store harvesting - catches LaZagne and infostealers by behaviour
category: behaviour
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1555, T1552.001, T1539, T1555.003]
data_source: CrowdStrike FDR file access events
suppression:
  fields: [host.id, process.entity_id]
  duration: 2h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
Infostealers and credential tools (LaZagne and the broad stealer family, and secret scanners pointed at a profile) read from many different credential locations in one pass: browser login databases, token and cookie stores, SSH and cloud credential files, and password-manager vaults. This counts the number of distinct credential-store types one process touches in a short window. Reaching several unrelated ones is harvesting, not normal app behaviour, whatever the binary is called.

## Query
Run every 10 minutes with a 15-minute lookback.
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.action IN ("FileOpenInfo", "FsPostOpen") AND file.path IS NOT NULL
| EVAL p = TO_LOWER(file.path),
       process.name = TO_LOWER(COALESCE(process.name, crowdstrike.ContextBaseFileName, "unknown"))
// browsers read their own and (on import) each other's stores; IDEs read SSH, kube and cloud config together
| WHERE process.name NOT IN ("chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "code.exe", "code")
| EVAL store = CASE(
    p LIKE """*\\user data\\*\\login data*""" OR p LIKE """*\\user data\\*\\cookies*""" OR p LIKE """*\\user data\\*\\web data*"""
      OR p LIKE "*/.config/google-chrome/*" OR p LIKE "*/.config/chromium/*", "chromium",
    p LIKE "*key4.db" OR p LIKE "*logins.json" OR p LIKE "*cookies.sqlite", "firefox",
    p RLIKE """.*[/\\]id_(rsa|dsa|ecdsa|ed25519)""", "ssh_private_key",
    p LIKE """*\\.aws\\credentials*""" OR p LIKE "*/.aws/credentials*" OR p LIKE "*msal_token_cache*" OR p LIKE "*accesstokens.json*"
      OR (p LIKE "*gcloud*" AND (p LIKE "*credentials*" OR p LIKE "*access_tokens*")), "cloud",
    p LIKE """*\\.kube\\config*""" OR p LIKE "*/.kube/config*", "kube",
    p RLIKE """.*\.(kdbx|ppk|ovpn|keychain-db)""", "vault_or_key",
    p LIKE """*\\microsoft\\credentials\\*""" OR p LIKE """*\\microsoft\\vault\\*""" OR p LIKE """*\\microsoft\\protect\\*""", "windows_cred",
    NULL)
| WHERE store IS NOT NULL
| STATS store_types = COUNT_DISTINCT(store),
        files = COUNT_DISTINCT(file.path),
        stores = VALUES(store),
        pname = VALUES(process.name),
        host.name = VALUES(host.name)
    BY host.id, process.entity_id, BUCKET(@timestamp, 10 minutes)
| WHERE store_types >= 3
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(FileOpenInfo|FsPostOpen)$/ TargetFileName=*
| pname := lower(ContextBaseFileName)
| default(field=pname, value="unknown", replaceEmpty=true)
// browsers read their own and (on import) each other's stores; IDEs read SSH, kube and cloud config together
| !in(field="pname", values=["chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "code.exe", "code"])
| case {
    TargetFileName=/\\user data\\.*\\(login data|cookies|web data)|\/\.config\/(google-chrome|chromium)\//i
      | store := "chromium";
    TargetFileName=/(key4\.db|logins\.json|cookies\.sqlite)$/i
      | store := "firefox";
    TargetFileName=/[\/\\]id_(rsa|dsa|ecdsa|ed25519)$/i
      | store := "ssh_private_key";
    (TargetFileName=/\\\.aws\\credentials|\/\.aws\/credentials|msal_token_cache|accesstokens\.json/i
       OR (TargetFileName=/gcloud/i AND TargetFileName=/credentials|access_tokens/i))
      | store := "cloud";
    TargetFileName=/\\\.kube\\config|\/\.kube\/config/i
      | store := "kube";
    TargetFileName=/\.(kdbx|ppk|ovpn|keychain-db)$/i
      | store := "vault_or_key";
    TargetFileName=/\\microsoft\\(credentials|vault|protect)\\/i
      | store := "windows_cred";
  }
| bucket_start := @timestamp - (@timestamp % 600000)
| groupBy([aid, ContextProcessId, bucket_start], function=[count(store, distinct=true, as=store_types),
                                                          count(TargetFileName, distinct=true, as=files),
                                                          collect([store, pname, ComputerName])], limit=max)
| test(store_types >= 3)
| bucket_start := formatTime(format="%F %T", field=bucket_start, timezone="Australia/Sydney")
```
SSH counts only private keys (`id_rsa`, not `id_rsa.pub`, `config` or `known_hosts`), and the key-file type leaves out `.pem` and `.key`, which TLS clients and servers read constantly. Counting per process instance (`process.entity_id`) stops a browser, an SSH client and a cloud CLI on the same host from adding up to three.

## Suppression
Suppress by `host.id`, `process.entity_id` for 2h. Alerts missing a key field are not suppressed. Aggregating rule. Harvesting spans buckets; a different process still alerts. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- Backup and sync agents, and security tools that inventory credentials, read several stores legitimately. These are few and named; exclude them inline by process name.
- Browsers are excluded by name: they read their own stores and, when importing, other browsers' stores. VS Code is excluded because its extensions read SSH, kube and cloud config in one process. Name exclusions only work when the event carries a process name.

## Triage
- A single process reading browser, SSH and cloud credentials in one pass is theft. Identify it, isolate the host, and treat every credential on that host as compromised: rotate SSH keys, cloud credentials and saved passwords for that user.

## Test
Run LaZagne or a multi-store secret scan on a lab host and confirm three or more store types are counted.
