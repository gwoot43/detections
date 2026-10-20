---
id: L09
name: Suspicious kernel module load or rootkit indicator
category: endpoint-linux
status: todo
severity: high
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1547.006, T1014, T1205.002]
data_source: CrowdStrike FDR ProcessRollup2 (Linux)
suppression:
  fields: [host.id]
  duration: 24h
  missing_fields: do_not_suppress
---
## Why this is high fidelity
Loading a kernel module from a user-writable path, or the shape of an eBPF-based rootkit loader, is rare and high impact. On a managed fleet, module loads come from the package manager and DKMS, not from a shell in `/tmp`.

## Query
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
| WHERE event.action == "processrollup2" AND host.os.type == "linux"
| EVAL cmd = TO_LOWER(COALESCE(process.command_line, "")), pname = TO_LOWER(process.name), parent = TO_LOWER(COALESCE(process.parent.name, ""))
// insmod and modprobe are symlinks to kmod on most distributions, so match the invoked name in the command line as well
| EVAL insmod_call = pname == "insmod" OR cmd LIKE "insmod *" OR cmd LIKE "*/insmod *" OR cmd LIKE "*kmod insert *",
       modprobe_call = pname == "modprobe" OR cmd LIKE "modprobe *" OR cmd LIKE "*/modprobe *"
| WHERE insmod_call    // any insmod outside package tooling is worth a look; scoped by parent below
   OR (modprobe_call AND (cmd LIKE "*/tmp/*" OR cmd LIKE "*/dev/shm/*" OR cmd LIKE "*/var/tmp/*" OR cmd LIKE "*/home/*"))
   OR (cmd LIKE "*bpftool*" AND (cmd LIKE "*prog load*" OR cmd LIKE "*map create*"))
   OR (cmd LIKE "*/sys/kernel/debug/*" AND (cmd LIKE "*echo*" OR cmd LIKE "*>*"))
   OR (cmd LIKE "*ld_preload*" AND (cmd LIKE "*/tmp/*" OR cmd LIKE "*/dev/shm/*"))
| WHERE parent NOT IN ("dkms", "apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "systemd-udevd", "cloud-init", "falcon-sensor", "falcond")
| KEEP @timestamp, host.id, host.name, user.name, parent, pname, process.command_line, _id, _version, _index
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Lin
| case {
    (FileName=/^insmod$/i OR CommandLine=/^insmod |\/insmod |kmod insert /i)
      | finding := "insmod";
    (FileName=/^modprobe$/i OR CommandLine=/^modprobe |\/modprobe /i)
      | CommandLine=/\/tmp\/|\/dev\/shm\/|\/var\/tmp\/|\/home\//i
      | finding := "modprobe from user-writable path";
    CommandLine=/bpftool/i CommandLine=/prog load|map create/i
      | finding := "bpftool program load or map create";
    CommandLine=/\/sys\/kernel\/debug\//i CommandLine=/echo|>/i
      | finding := "write to debugfs";
    CommandLine=/ld_preload/i CommandLine=/\/tmp\/|\/dev\/shm\//i
      | finding := "LD_PRELOAD from temp directory";
  }
| !in(field="ParentBaseFileName", ignoreCase=true, values=["dkms", "apt", "apt-get", "dpkg", "yum", "dnf", "rpm", "systemd-udevd",
                                                           "cloud-init", "falcon-sensor", "falcond"])
| select([@timestamp, aid, ComputerName, UserName, finding, ParentBaseFileName, FileName, CommandLine])
```

## Suppression
Suppress by `host.id` for 24h. Alerts missing a key field are not suppressed. Modules reload at every boot. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- DKMS building GPU or VPN modules, and the Falcon sensor loading its own module, are excluded by parent. Hardware agents (`nvidia`, `vmware`) at boot run under `systemd-udevd`, also excluded.

## Triage
- A module from `/tmp` is a rootkit until disproven. Capture the file, do not reboot (some rootkits only persist in memory), engage IR.

## Test
Build and `insmod` a hello-world module from `/tmp` on a lab host.
