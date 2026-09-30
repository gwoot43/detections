---
id: L11
name: PAM module or NSS configuration changed (authentication backdoor)
category: endpoint-linux
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1556.003, T1543]
data_source: CrowdStrike FDR file and process events (Linux)
suppression:
  fields: [host.name, f]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Replacing a PAM module or editing `/etc/pam.d` lets an attacker accept a magic password or log every password entered. Editing `/etc/nsswitch.conf` or a PAM config to load an attacker module is the same idea. These files change only through the package manager and configuration management, which have recognisable parents.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE host.os.type == "linux" AND event.action IN ("ProcessRollup2", "CriticalFileModified", "NewFileWritten")
| EVAL cmd = TO_LOWER(TO_STRING(COALESCE(process.command_line, ""))),
       pname = TO_LOWER(TO_STRING(COALESCE(process.name, ""))),
       parent = TO_LOWER(TO_STRING(COALESCE(process.parent.name, ""))),
       f = TO_LOWER(TO_STRING(COALESCE(file.path, "")))
| WHERE (f LIKE "/etc/pam.d/*" OR f LIKE "/lib/security/*" OR f LIKE "/lib64/security/*"
         OR f LIKE "/usr/lib/security/*" OR f LIKE "*/pam_*.so" OR f == "/etc/nsswitch.conf")
     OR ((cmd LIKE "*/etc/pam.d/*" OR cmd LIKE "*pam_*.so*" OR cmd LIKE "*nsswitch.conf*")
         AND (cmd LIKE "*echo*" OR cmd LIKE "*>>*" OR cmd LIKE "*tee*" OR cmd LIKE "*sed -i*" OR cmd LIKE "*cp *" OR cmd LIKE "*mv *" OR pname IN ("vi", "vim", "nano")))
| WHERE NOT (parent IN ("apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "ansible", "ansible-playbook", "puppet", "chef-client", "salt-minion", "cloud-init", "authselect", "pam-auth-update"))
| KEEP @timestamp, host.name, user.name, event.action, parent, pname, process.command_line, f
```

## Suppression
Suppress by `host.name`, `f` for 1h. Alerts missing a key field are not suppressed. One edit can produce several file events; a different file or host still alerts.

## Known false positives / exclusions
- Package updates and configuration management, excluded by parent. The `authselect` and `pam-auth-update` helpers, also excluded. Add your deployment user if it edits PAM over SSH, keyed by user plus source host.

## Triage
- Diff the file against a known-good baseline. A new or modified module is a credential backdoor; capture it, treat the host as compromised, and rotate credentials used there.

## Test
Add a comment line to a file under /etc/pam.d on a lab host with an editor, then revert.
