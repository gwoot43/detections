---
id: B09
name: Host discovery command burst, labelled when it includes domain enumeration - catches post-exploitation recon and loaders by behaviour
category: behaviour
status: todo
language: esql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1033, T1016, T1057, T1082, T1087, T1049, T1069.002, T1482]
data_source: CrowdStrike FDR ProcessRollup2
suppression:
  fields: [host.id, user.name, label]
  duration: 1h
  missing_fields: do_not_suppress
---
## Why this is behavioural and high fidelity
After landing on a host, an operator or a loader runs a rapid series of built-in discovery commands to orient: host, network, process, account and domain reconnaissance. A real user runs one or two of these occasionally. This counts the number of distinct discovery utilities a single host runs in a short window, so it catches the orientation burst regardless of which script or framework drove it.

Two tiers, in the `label` column:
- **`domain_enumeration`:** The command line carries one of the high-signal arguments (`net group` or `net user` with `/domain`, or `domain admins`; `nltest /dclist` or `/domain_trusts`; `whoami /priv`, `/groups` or `/all`; `setspn -q`) inside a burst, or three different kinds of them in one window even without a full burst. Enumerating Domain Admins and trusts is what an operator does next, and not what a normal user does.
- **`discovery_burst`:** a burst of six or more distinct discovery utilities with none of those arguments.

## Query
Run every 10 minutes with a 15-minute lookback.
```esql
FROM logs-yourorg-crowdstrike-data-default*
| WHERE event.action == "processrollup2" AND host.os.type == "windows"
| EVAL pname = TO_LOWER(process.name),
       cmd = TO_LOWER(COALESCE(process.command_line, "")),
       parent = TO_LOWER(COALESCE(process.parent.name, "")),
       grandparent = TO_LOWER(COALESCE(data.GrandParentBaseFileName, ""))
// SCCM and Intune scripts run inventory commands in bursts
| WHERE parent NOT IN ("ccmexec.exe", "intunemanagementextension.exe", "agentexecutor.exe")
  AND grandparent NOT IN ("ccmexec.exe", "intunemanagementextension.exe", "agentexecutor.exe")
// net.exe re-launches as net1.exe and query.exe as quser/qwinsta, so each pair counts once
| EVAL recon = CASE(
    pname IN ("net.exe", "net1.exe"), "net",
    pname IN ("quser.exe", "qwinsta.exe", "query.exe"), "sessions",
    pname IN ("whoami.exe", "hostname.exe", "systeminfo.exe", "tasklist.exe", "ipconfig.exe",
              "nltest.exe", "arp.exe", "route.exe", "netstat.exe", "nbtstat.exe",
              "dsquery.exe", "setspn.exe", "klist.exe", "cmdkey.exe"), pname,
    NULL)
| WHERE recon IS NOT NULL
// high-signal domain-enumeration arguments
| EVAL ad_recon = CASE(
    pname IN ("net.exe", "net1.exe") AND (cmd LIKE "*group*/domain*" OR cmd LIKE "*user*/domain*" OR cmd LIKE "*domain admins*"), "net-domain",
    pname == "nltest.exe" AND (cmd LIKE "*/dclist*" OR cmd LIKE "*/domain_trusts*"), "nltest",
    pname == "whoami.exe" AND (cmd LIKE "*/priv*" OR cmd LIKE "*/groups*" OR cmd LIKE "*/all*"), "whoami",
    pname == "setspn.exe" AND cmd LIKE "*-q*", "setspn",
    NULL)
// user.name is DOMAIN\user or user depending on enrichment; group on the bare, lowercased name
| EVAL user.name = TO_LOWER(MV_LAST(SPLIT(user.name, "\\")))
| STATS distinct_recon = COUNT_DISTINCT(recon),
        ad_recon_kinds = COUNT_DISTINCT(ad_recon),
        commands = VALUES(recon),
        ad_commands = VALUES(ad_recon),
        parents = VALUES(parent),
        host.name = VALUES(host.name)
    BY host.id, user.name
| WHERE distinct_recon >= 6 OR ad_recon_kinds >= 3
| EVAL label = CASE(ad_recon_kinds >= 1, "domain_enumeration", "discovery_burst")
```

**CrowdStrike (Falcon LogScale / Advanced Event Search)**
```logscale
#event_simpleName=/^(ProcessRollup2|SyntheticProcessRollup2)$/ event_platform=Win
// SCCM and Intune scripts run inventory commands in bursts
| !in(field="ParentBaseFileName", ignoreCase=true, values=["ccmexec.exe", "intunemanagementextension.exe", "agentexecutor.exe"])
| !in(field="GrandParentBaseFileName", ignoreCase=true, values=["ccmexec.exe", "intunemanagementextension.exe", "agentexecutor.exe"])
| pname := lower(FileName)
// net.exe re-launches as net1.exe and query.exe as quser/qwinsta, so each pair counts once
| case {
    in(field="pname", values=["net.exe", "net1.exe"]) | recon := "net";
    in(field="pname", values=["quser.exe", "qwinsta.exe", "query.exe"]) | recon := "sessions";
    in(field="pname", values=["whoami.exe", "hostname.exe", "systeminfo.exe", "tasklist.exe", "ipconfig.exe",
                              "nltest.exe", "arp.exe", "route.exe", "netstat.exe", "nbtstat.exe",
                              "dsquery.exe", "setspn.exe", "klist.exe", "cmdkey.exe"]) | recon := pname;
  }
// high-signal domain-enumeration arguments
| case {
    in(field="pname", values=["net.exe", "net1.exe"]) CommandLine=/group.*\/domain|user.*\/domain|domain admins/i
      | ad_recon := "net-domain";
    pname="nltest.exe" CommandLine=/\/dclist|\/domain_trusts/i | ad_recon := "nltest";
    pname="whoami.exe" CommandLine=/\/priv|\/groups|\/all/i | ad_recon := "whoami";
    pname="setspn.exe" CommandLine=/-q/i | ad_recon := "setspn";
    *;
  }
// UserName is DOMAIN\user or user; group on the bare, lowercased name
| case {
    UserName=/(?<uname>[^\\]*)$/ | uname := lower(uname);
    *;
  }
| default(field=uname, value="unknown", replaceEmpty=true)
| groupBy([aid, uname], function=[count(recon, distinct=true, as=distinct_recon),
                                  count(ad_recon, distinct=true, as=ad_recon_kinds),
                                  collect([recon, ad_recon, ParentBaseFileName, ComputerName])], limit=max)
// Deliberately no * branch: an event passes if any branch matches.
| case { test(distinct_recon >= 6); test(ad_recon_kinds >= 3); }
| case {
    test(ad_recon_kinds >= 1) | label := "domain_enumeration";
    * | label := "discovery_burst";
  }
```
These are native Windows utilities, so the signal is the count and speed, not any one command. `net.exe` re-launches as `net1.exe` with the same arguments, so `ad_recon_kinds` counts the pair once. `reg.exe`, `wmic.exe` and `fsutil.exe` are not counted: installers and inventory scripts call them constantly and they are not discovery-specific. Counts run over the whole 15-minute lookback, not fixed buckets, so a burst that crosses a bucket edge isn't split in two. Tune the threshold on your estate.

## Suppression
Suppress by `host.id`, `user.name`, `label` for 1h. Alerts missing a key field are not suppressed. Aggregating rule: each 10-minute run overlaps the last, and suppression folds the repeat into the open alert. A different host or user still alerts. `label` is in the key so a generic burst that turns into domain enumeration raises a new alert. `host.id` is the Falcon agent ID and is always present; `host.name` is filled only when the integration's host metadata enrichment is on.

## Known false positives / exclusions
- Login scripts, inventory agents and support scripts run several of these at logon. SCCM and Intune are excluded by parent and grandparent; add your RMM or login-script host the same way.
- Admins troubleshooting. Context plus the parent process usually separates them; a scripted parent spawning the burst is the suspicious case.
- Credentialed vulnerability scanners and AD engineers running `net` and `nltest` against the domain. Exclude the scanner's service account, and AD engineers only as a (host, user) pair on the admin jump host.

## Triage
- Look at the parent process. A burst spawned by a script host, an Office child or an unsigned binary is post-exploitation orientation. **`domain_enumeration`:** a normal user should never enumerate Domain Admins or domain trusts; look for Kerberoasting (I03) and AD tooling (W09) from the same host. Pivot to what ran before it (the initial access) and after it (lateral movement, B04, or credential access, B08).

## Test
Run six or more of the listed commands in sequence on a lab host and confirm the rule fires.
