---
id: LATMOV-01
name: SMB spoken by a user-mode process (Impacket, smbclient, custom), or the Impacket exec output artifact - by behaviour, not name
language: cql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1021.002, T1570, T1569.002]
data_source: CrowdStrike FDR NetworkConnectIP4/IP6 and ProcessRollup2
suppression:
  fields: [host.id, finding]
  duration: 2h
  missing_fields: do_not_suppress
---
Two behaviours, no tool names:

- **smb_from_user_process** - on Windows, normal SMB (a mapped drive, `net use`, Explorer) is spoken by the kernel redirector, so Falcon attributes it to `System`. A *user-mode* process making an outbound SMB connection (TCP 445) is speaking SMB itself: that is Impacket (its python process opens the socket), Samba's `smbclient`, or any custom SMB tool. Rarity across the fleet removes the handful of legitimate user-mode SMB talkers (a backup agent, a sync client), so what is left is a program that normally doesn't do this, on few hosts.
- **impacket_exec_output** - the Impacket exec modules (psexec/smbexec/wmiexec/atexec/dcomexec) all redirect their command output to a `__`-prefixed file on an admin share so they can read it back, i.e. the sequence `$\__` in a command line. That is how the tool works, not what it is called, and it is strong on its own.

CS16 and B04 cover the same tooling by rarity and by name; this is the sharper, name-free cut: the discriminator is *who* spoke SMB, not which program.

Run hourly over the last 2 hours (two runs cover each window).
```logscale
//Rarity table: how many hosts run each process speaking SMB or carrying the exec artifact
defineTable(name="proc_hosts", start=2h, include=[proc, hosts], query={
    #event_simpleName=/^(NetworkConnectIP4|NetworkConnectIP6|ProcessRollup2)$/ event_platform=Win
    | (RemotePort=445 ConnectionDirection=0) OR CommandLine=/\$\\__/
    | proc := lower(ContextBaseFileName)
    | default(field=proc, value=lower(ImageFileName))
    | proc!=/^(system|svchost\.exe)$/
    | groupBy([proc], function=count(aid, distinct=true, as=hosts), limit=max)
})
| #event_simpleName=/^(NetworkConnectIP4|NetworkConnectIP6|ProcessRollup2)$/ event_platform=Win
//Classify each event as SMB-from-a-process or the exec artifact
| case {
    #event_simpleName=/^NetworkConnectIP/ RemotePort=445 ConnectionDirection=0 | cidr(RemoteAddressIP4, subnet=["10.0.0.0/8","172.16.0.0/12","192.168.0.0/16"]) | kind := "smb" ;
    #event_simpleName=ProcessRollup2 CommandLine=/\$\\__/ | kind := "exec" ;
    * | kind := "" ;
  }
| kind!=""
//The connecting process; native SMB is the kernel (System), so drop it and the service host
| proc := lower(ContextBaseFileName)
| default(field=proc, value=lower(ImageFileName))
| proc!=/^(system|svchost\.exe)$/
| is_exec := if(kind=="exec", then=1, else=0)
//One row per host and process
| groupBy([aid, proc], function=[count(RemoteAddressIP4, distinct=true, as=smb_targets), max(is_exec, as=exec_artifact),
    min(@timestamp, as=first_seen), max(@timestamp, as=last_seen), collect([CommandLine, RemoteAddressIP4], limit=50)], limit=max)
//Attach the fleet-wide host count for this process
| match(table="proc_hosts", field=proc, column=proc, include=[hosts], strict=false)
| default(field=hosts, value=1)
//Alert: the exec artifact on its own; or user-process SMB when the program is rare (<=3 hosts).
//Deliberately no * branch: this case is the threshold.
| case {
    test(exec_artifact >= 1) ;
    test(smb_targets >= 1) | test(hosts <= 3) ;
  }
| match(file="aid_master_main.csv", field=aid, include=[ComputerName], strict=false)
| last_seen := formatTime("%Y-%m-%d %H:%M:%S", field=last_seen, timezone="Australia/Sydney")
| select([ComputerName, proc, smb_targets, exec_artifact, hosts, CommandLine, RemoteAddressIP4, last_seen])
```
```esql
FROM logs-yourorg-crowdstrike-data-default*
// Two behaviours: a user-mode process making outbound SMB to an internal host, or the Impacket exec output artifact.
| WHERE (event.action IN ("networkconnectip4", "networkconnectip6")
         AND destination.port == 445 AND data.ConnectionDirection == "0"
         AND CIDR_MATCH(destination.ip, "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
         AND process.name IS NOT NULL AND NOT process.name IN ("System", "svchost.exe"))
     OR (event.action == "processrollup2" AND TO_LOWER(process.command_line) RLIKE """.*\$\\__.*""")
| EVAL proc = TO_LOWER(process.name), is_exec = event.action == "processrollup2"
// One row per host and process
| STATS first_seen = MIN(@timestamp), last_seen = MAX(@timestamp),
        smb_targets = COUNT_DISTINCT(destination.ip),
        exec_artifact = MAX(CASE(is_exec, 1, 0)),
        command_lines = VALUES(process.command_line), host.name = VALUES(host.name)
    BY host.id, proc
// Rarity: how many hosts run this process with either behaviour, before the threshold
| INLINE STATS hosts = COUNT_DISTINCT(host.id) BY proc
// New in the last 2 hours. Exec artifact alerts on its own; user-process SMB when the program is rare (<=3 hosts).
| WHERE last_seen >= NOW() - 2 hours
| EVAL finding = CASE(exec_artifact == 1, "impacket_exec_output",
                      smb_targets >= 1 AND hosts <= 3, "smb_from_user_process", NULL)
| WHERE finding IS NOT NULL
| KEEP first_seen, last_seen, host.id, host.name, proc, finding, smb_targets, hosts, command_lines
```
No count to baseline for the exec artifact. The SMB threshold is `hosts <= 3`; set it from the baseline below. Suppress by host and finding for 2h.

## Before turning it on
- Confirm native SMB is attributed to `System`, not to a user process, on your sensor:
  ```esql
  FROM logs-yourorg-crowdstrike-data-default*
  | WHERE event.action == "networkconnectip4" AND destination.port == 445 AND data.ConnectionDirection == "0"
  | STATS connections = COUNT(*), hosts = COUNT_DISTINCT(host.id) BY process.name
  | SORT connections DESC
  ```
  The top rows are your legitimate SMB talkers. `System` is native SMB (excluded). Named user processes that appear on many hosts (a backup agent, a sync client) are what rarity removes; anything that runs on 3 or fewer hosts is the signal. Set the `hosts <= 3` from this.
- Confirm the `$\__` artifact in a lab: run one Impacket exec module against a test host and check the child `cmd.exe` command line in Falcon carries `\\<ip>\ADMIN$\__<timestamp>`.

## What it misses
- A tool that uses the native Windows SMB stack to move (it would show as `System`): `net use` plus a hand-run command, `sc \\host`, a mapped drive. B04's protocol fan-out and 10's share access catch those by volume.
- SMB to an external host (rare, but `fc00::/7` and the private ranges only cover internal here on purpose).
- An Impacket module told to write its output somewhere other than a `__` admin-share file.
- Non-Windows hosts; the `System`-vs-user-process discriminator is Windows-only. On Linux, Samba's `smbclient` and Impacket still open 445 from their own process, but legitimate Linux SMB clients do too, so there it needs rarity alone (drop `event_platform=Win` and lean on `hosts <= 3`).

## When it fires
`proc` is the program that spoke SMB (`python.exe`, a frozen Impacket exe, a renamed binary, `smbclient`). `impacket_exec_output` with the `$\__` command line is remote code execution: read `command_lines` for what ran, and `ParentBaseFileName` on the source for how (`services.exe` = psexec/smbexec, `WmiPrvSE.exe` = wmiexec, `taskeng.exe`/`svchost.exe` = atexec). Pivot on the process for what followed, and check 7045 (service install) on the target. Treat the account and source host as compromised.
