---
id: L09
name: Suspicious kernel module load or rootkit indicator
category: endpoint-linux
status: todo
severity: high
language: esql
index: logs-crowdstrike.fdr-*
mitre: [T1547.006, T1014, T1205.002]
data_source: CrowdStrike FDR ProcessRollup2 (Linux)
---
## Why this is high fidelity
Loading a kernel module from a user-writable path, or the shape of an eBPF-based rootkit loader, is rare and high impact. On a managed fleet, module loads come from the package manager and DKMS, not from a shell in `/tmp`.

## Query
```esql
FROM logs-crowdstrike.fdr-* METADATA _id, _index, _version
| WHERE event.action == "ProcessRollup2" AND host.os.type == "linux"
| EVAL cmd = TO_LOWER(process.command_line), pname = TO_LOWER(process.name), parent = TO_LOWER(process.parent.name)
| WHERE (pname IN ("insmod", "modprobe") AND (cmd LIKE "*/tmp/*" OR cmd LIKE "*/dev/shm/*" OR cmd LIKE "*/var/tmp/*" OR cmd LIKE "*/home/*" OR cmd LIKE "*./*"))
   OR (pname == "insmod")   // any insmod outside package tooling is worth a look; scope by parent below
   OR (cmd LIKE "*bpftool*" AND (cmd LIKE "*prog load*" OR cmd LIKE "*map create*"))
   OR (cmd LIKE "*/sys/kernel/debug/*" AND (cmd LIKE "*echo*" OR cmd LIKE "*>*"))
   OR (cmd LIKE "*ld_preload*" AND (cmd LIKE "*/tmp/*" OR cmd LIKE "*/dev/shm/*"))
   OR (pname IN ("kmod") AND cmd LIKE "*insert*")
| WHERE NOT (parent IN ("dkms", "apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "systemd-udevd", "cloud-init", "falcon-sensor"))
| KEEP @timestamp, host.name, user.name, parent, pname, process.command_line
```

## Known false positives / exclusions
- DKMS building GPU or VPN modules, excluded by parent. Hardware agents (`nvidia`, `vmware`) at boot. Exclude the boot-time udev parent.

## Triage
- A module from `/tmp` is a rootkit until disproven. Capture the file, do not reboot (some rootkits only persist in memory), engage IR.

## Test
Build and `insmod` a hello-world module from `/tmp` on a lab host.
