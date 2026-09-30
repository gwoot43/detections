---
id: L05
name: Credential file access, SSH key harvesting or cloud metadata theft
category: endpoint-linux
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1003.008, T1552.004, T1552.005, T1552.001]
data_source: CrowdStrike FDR ProcessRollup2 and CriticalFileAccessed (Linux)
---
## Why this is high fidelity
`/etc/shadow` is read by `passwd`, `sshd`, `sudo` and PAM, never by `cat`, `python` or `curl`. Bulk searches for private keys and shell access to the instance metadata service are attacker moves on a server.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE host.os.type == "linux" AND event.action IN ("ProcessRollup2", "CriticalFileAccessed")
| EVAL cmd = TO_LOWER(process.command_line), pname = TO_LOWER(process.name), f = TO_LOWER(COALESCE(file.path, ""))
| WHERE (event.action == "CriticalFileAccessed" AND f IN ("/etc/shadow", "/etc/gshadow", "/etc/security/opasswd")
         AND NOT (pname IN ("sshd", "sudo", "su", "passwd", "chpasswd", "login", "unix_chkpwd", "systemd", "useradd", "usermod", "vipw")))
   OR (pname IN ("cat", "less", "more", "head", "tail", "cp", "vi", "vim", "nano", "python", "python3", "perl", "grep", "awk", "xxd", "base64") AND (cmd LIKE "*/etc/shadow*" OR cmd LIKE "*/etc/gshadow*"))
   OR (cmd LIKE "*169.254.169.254*" AND pname IN ("curl", "wget", "python", "python3", "perl", "bash", "sh"))
   OR (cmd LIKE "*metadata.google.internal*" AND cmd LIKE "*token*")
   OR (pname IN ("find", "grep", "egrep") AND (cmd LIKE "*id_rsa*" OR cmd LIKE "*id_ed25519*" OR cmd LIKE "*.pem*" OR cmd LIKE "*.ssh*" OR cmd LIKE "*-----begin*private*"))
   OR (cmd LIKE "*.aws/credentials*" OR cmd LIKE "*.kube/config*" OR cmd LIKE "*.docker/config.json*" OR cmd LIKE "*gcloud*credentials*")
| KEEP @timestamp, host.name, user.name, process.parent.name, pname, process.command_line, f
```

## Known false positives / exclusions
- Backup and compliance scanners reading credential stores. Exclude by the scanner's service account.
- Config management reading `.kube/config`. Exclude by parent.

## Triage
- Metadata access from a shell on a web server is SSRF or hands-on-keyboard. Rotate the instance role credentials and check cloud logs (C10) for use of the stolen token.

## Test
`cat /etc/shadow` as root on a lab host (produces the process branch).
