---
id: L06
name: Privilege escalation via SUID abuse, sudo misconfig or known exploit pattern
category: endpoint-linux
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1548.001, T1548.003, T1068]
data_source: CrowdStrike FDR ProcessRollup2 (Linux)
---
## Why this is high fidelity
GTFOBins escalation shapes, `sudo` run with the CVE-2021-3156 or CVE-2023-22809 patterns, and new SUID binaries appearing in world-writable paths are narrow and rarely benign.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "linux"
| EVAL cmd = TO_LOWER(process.command_line), pname = TO_LOWER(process.name), parent = TO_LOWER(process.parent.name)
| WHERE (pname == "sudo" AND (cmd LIKE "*sudoedit*-*" OR cmd LIKE "*\\*" OR cmd LIKE "*editor=*"))
   OR (parent IN ("sudo", "pkexec") AND pname IN ("sh", "bash", "dash", "python", "python3", "perl", "find", "vim", "vi", "nmap", "awk", "gdb", "tar", "zip", "less", "more", "man", "env") AND (cmd LIKE "*-c *" OR cmd LIKE "*exec*" OR cmd LIKE "*!sh*" OR cmd LIKE "*--interactive*" OR cmd LIKE "*/bin/sh*" OR cmd LIKE "*checkpoint=*"))
   OR (pname == "pkexec" AND parent NOT IN ("gnome-shell", "gdm", "systemd", "gnome-session-binary"))
   OR (cmd LIKE "*chmod*4755*" OR cmd LIKE "*chmod*u+s*" OR cmd LIKE "*chmod*2755*")
   OR (pname IN ("find") AND cmd LIKE "*-perm*" AND (cmd LIKE "*4000*" OR cmd LIKE "*-u=s*"))
   OR (cmd LIKE "*unshare*" AND cmd LIKE "*-r*" AND cmd LIKE "*bash*")
   OR (cmd LIKE "*capsh*" AND cmd LIKE "*--gid=0*" AND cmd LIKE "*--uid=0*")
| KEEP @timestamp, host.name, user.name, parent, pname, process.command_line
```

## Known false positives / exclusions
- Admins using `sudo vim` legitimately. The GTFOBins branch requires the escape sequence (`!sh`, `-c`, `exec`), which reduces this. Baseline the admin population.
- Installers running `chmod u+s` on their own binaries under `/usr/`. Exclude by parent package manager.

## Triage
- Confirm the escalation succeeded (subsequent root process from the same session). Check how the user got on the host (L03, SSH brute force in F04).

## Test
Atomic Red Team T1548.003 on a lab host.
