---
id: L04
name: Persistence via cron, systemd unit, shell profile or SSH authorized_keys
category: endpoint-linux
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1053.003, T1543.002, T1546.004, T1098.004]
data_source: CrowdStrike FDR ProcessRollup2 and CriticalFileModified (Linux)
suppression:
  fields: [host.id, user.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Falcon's Linux sensor emits `CriticalFileModified` for a curated set of sensitive files. The process branch catches persistence written through a shell. Package managers and config management are the only legitimate writers, and they have a recognisable parent.

`CriticalFileModified` carries no process name, so a package update cannot be told apart from an attacker there. The file branch is therefore limited to `authorized_keys` and `/etc/ld.so.preload`, which packages do not write. Cron, systemd and profile changes are taken from the process branch, where the writer is known:
- `crontab` installing from stdin (`… | crontab -`) or from a file in a temp directory, not `crontab -e` or `-l`.
- `systemctl enable` of a unit file that lives in a temp or home directory. Plain `systemctl enable`, `is-enabled` and `daemon-reload` run on every package install.
- Appending to a shell profile only when the line fetches, decodes or opens a socket. Installers append `PATH` exports all the time.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE host.os.type == "linux" AND event.action IN ("ProcessRollup2", "CriticalFileModified")
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, "")), pname = TO_LOWER(COALESCE(process.name, "")),
       parent = TO_LOWER(COALESCE(process.parent.name, "")), f = TO_LOWER(COALESCE(file.path, ""))
| WHERE (event.action == "CriticalFileModified" AND (f LIKE "*/.ssh/authorized_keys*" OR f == "/etc/ld.so.preload"))
   OR (event.action == "ProcessRollup2" AND (
          (pname == "crontab" AND (cmd LIKE "* -" OR cmd LIKE "*/tmp/*" OR cmd LIKE "*/dev/shm/*" OR cmd LIKE "*/var/tmp/*"))
       OR (cmd LIKE "*authorized_keys*" AND (cmd LIKE "*echo*" OR cmd LIKE "*>>*" OR cmd LIKE "*tee*" OR cmd LIKE "*curl*" OR cmd LIKE "*wget*"))
       OR (pname == "systemctl" AND cmd LIKE "* enable *" AND (cmd LIKE "*/tmp/*" OR cmd LIKE "*/dev/shm/*" OR cmd LIKE "*/var/tmp/*" OR cmd LIKE "*/home/*"))
       OR (cmd LIKE "*/etc/systemd/system/*" AND (cmd LIKE "*echo*" OR cmd LIKE "*>>*" OR cmd LIKE "*tee*" OR cmd LIKE "*cp *" OR cmd LIKE "*mv *"))
       OR (cmd LIKE "*ld.so.preload*" AND (cmd LIKE "*>*ld.so.preload*" OR cmd LIKE "*echo*" OR cmd LIKE "*tee*" OR cmd LIKE "*cp *" OR cmd LIKE "*mv *"))
       OR ((cmd LIKE "*.bashrc*" OR cmd LIKE "*.bash_profile*" OR cmd LIKE "*/etc/profile.d/*")
           AND (cmd LIKE "*>>*" OR cmd LIKE "*tee*")
           AND (cmd LIKE "*curl*" OR cmd LIKE "*wget*" OR cmd LIKE "*base64*" OR cmd LIKE "*/dev/tcp*" OR cmd LIKE "*nohup*" OR cmd LIKE "*alias sudo*"))
     ))
// CriticalFileModified has no parent, so this only filters the process branch
| WHERE parent NOT IN ("apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "ansible", "ansible-playbook", "puppet", "chef-client", "salt-minion", "cloud-init", "packer", "falcon-sensor")
| EVAL user.name = TO_LOWER(MV_LAST(SPLIT(user.name, "\\")))
| KEEP @timestamp, host.id, host.name, user.name, event.action, parent, pname, process.command_line, f
```

## Suppression
Suppress by `host.id`, `user.name` for 1h. Alerts missing a key field are not suppressed. Persistence is usually set up with several commands at once. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on. `user.name` is reduced to the bare, lowercased account name, since enrichment writes either `DOMAIN\user` or `user`.

## Known false positives / exclusions
- Config management and cloud-init, excluded by parent above. Add your deployment user if it writes cron over SSH, then exclude by user plus source host.
- `authorized_keys` written at first boot by cloud-init or by a key-rotation job. The file event has no process, so exclude those by host group or time window, not by file.
- Ansible's cron module installs via `crontab /tmp/…`. Exclude its service account.

## Triage
- Read the new cron line, unit file or key. A key you do not recognise on a server is a compromised host.

## Test
Add a benign crontab line on a lab host, then remove it.
