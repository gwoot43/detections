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
  fields: [host.name, user.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Falcon's Linux sensor emits `CriticalFileModified` for a curated set of persistence files, which removes the guessing. The process branch catches the same intent when the write comes through an editor or shell redirect. Package managers and config management are the only legitimate writers, and they have a recognisable parent.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE host.os.type == "linux" AND event.action IN ("ProcessRollup2", "CriticalFileModified")
| EVAL cmd = TO_LOWER(process.command_line), pname = TO_LOWER(process.name), parent = TO_LOWER(process.parent.name),
       f = TO_LOWER(COALESCE(file.path, ""))
| WHERE (event.action == "CriticalFileModified" AND (f LIKE "/etc/cron*" OR f LIKE "/var/spool/cron/*" OR f LIKE "/etc/systemd/system/*" OR f LIKE "/usr/lib/systemd/system/*" OR f LIKE "*/.ssh/authorized_keys*" OR f LIKE "/etc/rc.local" OR f LIKE "*/.bashrc" OR f LIKE "*/.bash_profile" OR f LIKE "*/.profile" OR f LIKE "/etc/ld.so.preload" OR f LIKE "/etc/init.d/*" OR f LIKE "/etc/update-motd.d/*"))
   OR (event.action == "ProcessRollup2" AND (
          (pname == "crontab" AND NOT (cmd LIKE "* -l*"))
       OR (cmd LIKE "*authorized_keys*" AND (cmd LIKE "*echo*" OR cmd LIKE "*>>*" OR cmd LIKE "*tee*" OR cmd LIKE "*curl*" OR cmd LIKE "*wget*"))
       OR (pname == "systemctl" AND (cmd LIKE "*enable*" OR cmd LIKE "*daemon-reload*"))
       OR (cmd LIKE "*/etc/systemd/system/*" AND (cmd LIKE "*echo*" OR cmd LIKE "*>>*" OR cmd LIKE "*tee*" OR cmd LIKE "*cp *" OR cmd LIKE "*mv *"))
       OR (cmd LIKE "*ld.so.preload*")
       OR ((cmd LIKE "*.bashrc*" OR cmd LIKE "*/etc/profile.d/*") AND (cmd LIKE "*echo*" OR cmd LIKE "*>>*" OR cmd LIKE "*curl*" OR cmd LIKE "*base64*"))
     ))
| WHERE NOT (parent IN ("apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "ansible", "ansible-playbook", "puppet", "chef-client", "salt-minion", "cloud-init", "packer", "falcon-sensor"))
| KEEP @timestamp, host.name, user.name, event.action, parent, pname, process.command_line, f
```

## Suppression
Suppress by `host.name`, `user.name` for 1h. Alerts missing a key field are not suppressed. Persistence is usually set up with several commands at once.

## Known false positives / exclusions
- Config management and cloud-init, excluded by parent above. Add your deployment user if it writes cron over SSH, then exclude by user plus source host.

## Triage
- Read the new cron line, unit file or key. A key you do not recognise on a server is a compromised host.

## Test
Add a benign crontab line on a lab host, then remove it.
