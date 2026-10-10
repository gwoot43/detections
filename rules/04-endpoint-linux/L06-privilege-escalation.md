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
suppression:
  fields: [host.name, user.name]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
GTFOBins escalation shapes, `sudoedit` run with the CVE-2021-3156 pattern, SUID bits set on files in temp or home directories, and SUID enumeration by a non-root account are narrow and rarely benign.

What is no longer matched, because admins do it daily:
- `sudo bash -c`, `sudo sh -c` and any `sudo` command containing a backslash. The GTFOBins branch now requires a binary that should not hand out a shell (`vim`, `find`, `tar`, `awk`, `less` …) plus the escape.
- `chmod 2755` (setgid on shared directories) and SUID bits set by packages under `/usr`.
- `find / -perm -4000` run as root by compliance scanners. Root has no reason to hunt for SUID binaries to escalate; an unprivileged account does.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "linux"
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, "")), pname = TO_LOWER(process.name), parent = TO_LOWER(COALESCE(process.parent.name, ""))
// CVE-2021-3156 (Baron Samedit): sudoedit -s with a trailing backslash
| WHERE (cmd LIKE "*sudoedit*" AND (cmd LIKE "* -s*" OR cmd LIKE "* -i*") AND cmd LIKE """*\\*""")
   OR (parent IN ("sudo", "pkexec")
       AND pname IN ("find", "vim", "vi", "nmap", "awk", "gawk", "gdb", "tar", "zip", "less", "more", "man", "env", "python", "python3", "perl", "ruby", "lua")
       AND (cmd LIKE "*/bin/sh*" OR cmd LIKE "*/bin/bash*" OR cmd LIKE "*!sh*" OR cmd LIKE "*--interactive*" OR cmd LIKE "*checkpoint-action=exec*"
            OR cmd LIKE "*pty.spawn*" OR cmd LIKE "*-exec sh*" OR cmd LIKE "*-exec bash*"))
   // pkexec outside a desktop session; an empty command line is the PwnKit (CVE-2021-4034) shape
   OR (pname == "pkexec" AND (cmd == "" OR parent NOT IN ("gnome-shell", "gdm", "systemd", "gnome-session-binary")))
   OR (cmd LIKE "*chmod*" AND (cmd LIKE "*4755*" OR cmd LIKE "*4777*" OR cmd LIKE "*u+s*" OR cmd LIKE "* +s *")
       AND (cmd LIKE "*/tmp/*" OR cmd LIKE "*/dev/shm/*" OR cmd LIKE "*/var/tmp/*" OR cmd LIKE "*/home/*"))
   OR (pname == "find" AND cmd LIKE "*-perm*" AND (cmd LIKE "*4000*" OR cmd LIKE "*-u=s*") AND user.id != "0")
   OR (pname == "unshare" AND cmd LIKE "*-r*" AND cmd LIKE "*bash*")
   OR (cmd LIKE "*capsh*" AND cmd LIKE "*--gid=0*" AND cmd LIKE "*--uid=0*")
| KEEP @timestamp, host.name, user.name, user.id, parent, pname, process.command_line
```

## Suppression
Suppress by `host.name`, `user.name` for 1h. Alerts missing a key field are not suppressed. Escalation attempts are retried.

## Known false positives / exclusions
- Admins using `sudo vim` or `sudo less` legitimately. The GTFOBins branch requires the escape sequence in the command line, which reduces this. Baseline the admin population.
- Rootless container tooling calling `unshare -r`. Exclude by parent.
- A shell escape typed inside an interactive `sudo less` or `sudo man` session does not appear in the command line and is not caught here.

## Triage
- Confirm the escalation succeeded (subsequent root process from the same session). Check how the user got on the host (L03, or SSH authentication logs for brute force).

## Test
Run the Atomic Red Team T1548.003 test on a lab host.
