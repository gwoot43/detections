---
id: B08
name: Credential store harvesting (one process reading many secret locations)
category: behaviour
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1555, T1552.001, T1539, T1555.003]
data_source: CrowdStrike FDR file access events
suppression:
  fields: [host.name, process.name]
  duration: 2h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
Infostealers and credential tools (LaZagne and the broad stealer family, and secret scanners pointed at a profile) read from many different credential locations in one pass: browser login databases, token and cookie stores, SSH and cloud credential files, and password-manager vaults. This counts the number of distinct credential-store types one process touches in a short window. Reaching several unrelated ones is harvesting, not normal app behaviour, whatever the binary is called.

## Query
Run every 10 minutes with a 15-minute lookback.
```esql
FROM logs-crowdstrike.fdr-*
| WHERE event.category == "file" AND TO_LOWER(event.action) RLIKE ".*(open|read).*" AND file.path IS NOT NULL
| EVAL p = TO_LOWER(file.path)
| EVAL store = CASE(
    p LIKE "*\\login data*" OR p LIKE "*\\cookies*" OR p LIKE "*\\web data*" OR p RLIKE ".*/(cookies|logins)\\.(sqlite|json)", "browser",
    p LIKE "*\\.ssh\\*" OR p LIKE "*/.ssh/*" OR p RLIKE ".*id_(rsa|ecdsa|ed25519).*", "ssh",
    p LIKE "*\\.aws\\credentials*" OR p LIKE "*/.aws/credentials*" OR p LIKE "*\\.azure\\*" OR p LIKE "*/.config/gcloud/*", "cloud",
    p LIKE "*\\.kube\\config*" OR p LIKE "*/.kube/config*", "kube",
    p RLIKE ".*\\.(kdbx|keychain|key|pem|ppk|ovpn)$", "vault_or_key",
    p LIKE "*\\appdata\\*\\key4.db" OR p LIKE "*/.mozilla/*key*.db" OR p LIKE "*logins.json*", "firefox",
    p LIKE "*\\credentials\\*" OR p LIKE "*\\vault\\*" OR p LIKE "*\\protect\\*", "windows_cred",
    NULL)
| WHERE store IS NOT NULL
| STATS store_types = COUNT_DISTINCT(store),
        files = COUNT_DISTINCT(file.path),
        stores = VALUES(store)
    BY host.name, process.name, user.name, BUCKET(@timestamp, 10 minutes)
| WHERE store_types >= 3
```

## Suppression
Suppress by `host.name`, `process.name` for 2h. Alerts missing a key field are not suppressed. Aggregating rule. Harvesting spans buckets; a different process still alerts.

## Known false positives / exclusions
- Backup and sync agents, and security tools that inventory credentials, read several stores legitimately. These are few and named; exclude them inline by process name.
- A browser reading its own login data is one store type and does not reach the threshold of three unrelated types.

## Triage
- A single process reading browser, SSH and cloud credentials in one pass is theft. Identify it, isolate the host, and treat every credential on that host as compromised: rotate SSH keys, cloud credentials and saved passwords for that user.

## Test
Run LaZagne or a multi-store secret scan on a lab host and confirm three or more store types are counted.
