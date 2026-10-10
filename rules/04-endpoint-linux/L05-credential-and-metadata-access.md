---
id: L05
name: Credential file access, SSH key harvesting or cloud metadata theft
category: endpoint-linux
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1003.008, T1552.004, T1552.005, T1552.001]
data_source: CrowdStrike FDR ProcessRollup2 (Linux)
suppression:
  fields: [host.id, user.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
`/etc/shadow` is read by `passwd`, `sshd`, `sudo` and PAM, never by `cat`, `python` or `curl`. Searches for private keys, reads of cloud credential files by copy and dump tools, and shell requests for instance-role credentials are attacker moves on a server.

`CriticalFileAccessed` is not used. It carries no process name, so it cannot tell `sshd` reading `/etc/shadow` at every login from `cat` doing it. Metadata-service calls only count when they ask for credentials or tokens; bootstrap scripts query instance IDs and regions constantly.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE host.os.type == "linux" AND event.action == "ProcessRollup2"
| EVAL cmd = TO_LOWER(process.command_line), pname = TO_LOWER(process.name)
| WHERE (pname IN ("cat", "less", "more", "head", "tail", "cp", "vi", "vim", "nano", "python", "python3", "perl", "grep", "awk", "xxd", "base64") AND (cmd LIKE "*/etc/shadow*" OR cmd LIKE "*/etc/gshadow*"))
   // AWS / Azure / GCP instance credentials, not instance metadata in general
   OR ((cmd LIKE "*169.254.169.254*" OR cmd LIKE "*metadata.google.internal*" OR cmd LIKE "*fd00:ec2::254*")
       AND (cmd LIKE "*security-credentials*" OR cmd LIKE "*identity/oauth2/token*" OR cmd LIKE "*service-accounts*token*"))
   OR (pname IN ("find", "grep", "egrep") AND (cmd LIKE "*id_rsa*" OR cmd LIKE "*id_ed25519*" OR cmd LIKE "*id_ecdsa*" OR cmd LIKE "*.ppk*" OR cmd LIKE "*-----begin*private*"))
   // credential files read by copy, dump or transfer tools; kubectl, aws and gcloud read them as normal use
   OR (pname IN ("cat", "less", "more", "head", "tail", "cp", "scp", "curl", "wget", "base64", "xxd", "tar", "zip", "nc", "ncat")
       AND (cmd LIKE "*.aws/credentials*" OR cmd LIKE "*.kube/config*" OR cmd LIKE "*.docker/config.json*" OR cmd LIKE "*gcloud*credentials*"))
| EVAL user.name = TO_LOWER(MV_LAST(SPLIT(user.name, "\\")))
| KEEP @timestamp, host.id, host.name, user.name, process.parent.name, pname, process.command_line
```

## Suppression
Suppress by `host.id`, `user.name` for 1h. Alerts missing a key field are not suppressed. Credential harvesting runs as a burst of reads and searches. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on. `user.name` is reduced to the bare, lowercased account name, since enrichment writes either `DOMAIN\user` or `user`.

## Known false positives / exclusions
- Backup and compliance scanners reading credential stores. Exclude by the scanner's service account.
- Admins copying `.kube/config` to a new machine. Confirm with the admin.
- Old bootstrap scripts that fetch instance-role credentials with `curl`. Exclude by exact command line and fix the script.

## Triage
- Metadata access from a shell on a web server is SSRF or hands-on-keyboard. Rotate the instance role credentials and check cloud logs (C10) for use of the stolen token.

## Test
Read `/etc/shadow` with `cat` as root on a lab host.
