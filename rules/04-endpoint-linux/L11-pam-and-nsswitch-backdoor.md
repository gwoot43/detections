---
id: L11
name: PAM module or NSS configuration changed (authentication backdoor)
category: endpoint-linux
status: todo
severity: high
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1556.003, T1543]
data_source: CrowdStrike FDR file and process events (Linux)
suppression:
  fields: [host.id, f]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Replacing a PAM module or editing `/etc/pam.d` lets an attacker accept a magic password or log every password entered. Editing `/etc/nsswitch.conf` or a PAM config to load an attacker module is the same idea. These files change only through the package manager and configuration management, which have recognisable process names.

Two branches:
- **File writes** (`*FileWritten` events) of a PAM module or config by a known process that is not package or config tooling. On these events `process.name` is the writer. Events without a writer name are skipped, because a `libpam` update would otherwise alert on every host on patch day. `CriticalFileModified` is not used for the same reason: it has no process at all.
- **Process launches** that edit those files from a shell or editor, excluding package and config-management parents.

## Query
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE host.os.type == "linux" AND (event.action == "processrollup2" OR event.action LIKE "*filewritten")
| EVAL cmd = TO_LOWER(TO_STRING(COALESCE(process.command_line, ""))),
       pname = TO_LOWER(TO_STRING(COALESCE(process.name, ""))),
       parent = TO_LOWER(TO_STRING(COALESCE(process.parent.name, ""))),
       f = TO_LOWER(TO_STRING(COALESCE(file.path, "")))
| WHERE (event.action LIKE "*filewritten" AND pname != ""
         AND (f LIKE "/etc/pam.d/*" OR f LIKE "*/pam_*.so" OR f == "/etc/nsswitch.conf")
         AND pname NOT IN ("dpkg", "rpm", "yum", "dnf", "apt", "apt-get", "unattended-upgr", "packagekitd", "authselect", "pam-auth-update", "authconfig"))
   OR (event.action == "processrollup2"
       AND (cmd LIKE "*/etc/pam.d/*" OR cmd LIKE "*pam_*.so*" OR cmd LIKE "*nsswitch.conf*")
       AND (cmd LIKE "*echo*" OR cmd LIKE "*>>*" OR cmd LIKE "*tee*" OR cmd LIKE "*sed -i*" OR cmd LIKE "*cp *" OR cmd LIKE "*mv *" OR pname IN ("vi", "vim", "nano"))
       AND parent NOT IN ("apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "ansible", "ansible-playbook", "puppet", "chef-client", "salt-minion", "cloud-init", "authselect", "pam-auth-update"))
| KEEP @timestamp, host.id, host.name, user.name, event.action, parent, pname, process.command_line, f, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2|\w*FileWritten)$/ event_platform=Lin
| case {
    #event_simpleName=/FileWritten$/ ContextBaseFileName=/./
      TargetFileName=/^\/etc\/pam\.d\/|\/pam_.*\.so$|^\/etc\/nsswitch\.conf$/i
      | !in(field="ContextBaseFileName", ignoreCase=true, values=["dpkg", "rpm", "yum", "dnf", "apt", "apt-get", "unattended-upgr",
                                                                  "packagekitd", "authselect", "pam-auth-update", "authconfig"])
      | finding := "PAM or NSS file written";
    #event_simpleName=/ProcessRollup2$/ CommandLine=/\/etc\/pam\.d\/|pam_.*\.so|nsswitch\.conf/i
      | (CommandLine=/echo|>>|tee|sed -i|(cp|mv) /i OR FileName=/^(vi|vim|nano)$/i)
      | !in(field="ParentBaseFileName", ignoreCase=true, values=["apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "ansible", "ansible-playbook",
                                                                 "puppet", "chef-client", "salt-minion", "cloud-init", "authselect",
                                                                 "pam-auth-update"])
      | finding := "PAM or NSS file edited from shell or editor";
  }
| select([@timestamp, aid, ComputerName, UserName, #event_simpleName, finding, ParentBaseFileName, FileName, ContextBaseFileName, CommandLine,
         TargetFileName])
```

## Suppression
Suppress by `host.id`, `f` for 1h. Alerts missing a key field are not suppressed. One edit can produce several file events; a different file or host still alerts. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- Package updates and configuration management, excluded by writer name on file events and by parent on process events. Add your deployment user if it edits PAM over SSH, keyed by user plus source host.
- Older Linux sensors that do not send the writer name on file events lose the file branch; the process branch still works.

## Triage
- Diff the file against a known-good baseline. A new or modified module is a credential backdoor; capture it, treat the host as compromised, and rotate credentials used there.

## Test
Add a comment line to a file under /etc/pam.d on a lab host with an editor, then revert.
