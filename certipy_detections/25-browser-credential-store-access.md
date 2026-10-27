---
id: BROWSERCRED-01
name: Browser credential store named by a non-browser process (logins.json, key4.db, Login Data) - theft for lateral movement
language: cql
index: logs-yourorg-crowdstrike-data-default*
mitre: [T1555.003, T1539, T1550]
data_source: CrowdStrike FDR ProcessRollup2 (Windows and Linux)
suppression:
  fields: [host.name, user.name]
  duration: 12h
  missing_fields: do_not_suppress
---
**Catches:** something other than the browser copying, reading or decrypting a browser password store. Saved browser passwords and session state unlock internal apps, VPNs, cloud consoles and admin portals - so this is credential theft that feeds lateral movement and escalation.

The signal is simple: **a process names a browser credential file on its command line, and it isn't the browser.** The browser never passes `logins.json` or `Login Data` as an argument to itself, and almost nothing legitimate does - so a command line that mentions one is a copy, a decrypt tool, or an exfil command. No store-plus-keyfile pairing, no aggregation: one precise match.

The files, same names on Windows and Linux:
- **Firefox:** `logins.json` (the passwords), `key4.db`/`key3.db` (the NSS key that decrypts them), `signons.sqlite` (old).
- **Chromium (Chrome/Edge/Brave):** `Login Data` (passwords), `Web Data` (autofill) - matched path-qualified (`\Login Data`), so the plain words don't false-match.
- **Known dumpers**, for the ones that name the tool rather than the file: LaZagne, HackBrowserData, firefox_decrypt, firepwd, SharpChrome, SharpWeb, SharpDPAPI, WebBrowserPassView, DonPAPI.

Run every 5 minutes over the last 10. One alert per process start.
```logscale
#event_simpleName=ProcessRollup2 CommandLine=/(?<Match>logins\.json|key[34]\.db|signons\.sqlite|[\\\/]login data|[\\\/]web data|firefox_decrypt|firepwd|lazagne|hackbrowserdata|sharpchrome|sharpweb|sharpdpapi|webbrowserpassview|donpapi)/iF
// the browsers open their own stores; we want any OTHER process naming one
| ImageFileName!=/[\\\/](firefox|firefox-bin|firefox-esr|chrome|chromium|msedge|brave|opera|vivaldi|thunderbird|plugin-container|crashpad_handler|pingsender)(\.exe)?$/i
| select([@timestamp, ComputerName, UserName, ImageFileName, ParentBaseFileName, Match, CommandLine])
```
```esql
FROM logs-yourorg-crowdstrike-data-default* METADATA _id, _index, _version
// a browser credential file named on the command line (RLIKE can't do case-insensitive capture, so GROK runs the regex)
| WHERE event.action == "processrollup2"
| GROK process.command_line """(?i)(?<matched>logins\.json|key[34]\.db|signons\.sqlite|[\\/]login data|[\\/]web data|firefox_decrypt|firepwd|lazagne|hackbrowserdata|sharpchrome|sharpweb|sharpdpapi|webbrowserpassview|donpapi)"""
| WHERE matched IS NOT NULL
// the browsers open their own stores; we want any OTHER process naming one
| EVAL pname = TO_LOWER(COALESCE(process.name, ""))
| WHERE NOT pname IN ("firefox", "firefox-bin", "firefox-esr", "chrome", "chrome.exe", "chromium", "chromium.exe",
                      "msedge.exe", "brave", "brave.exe", "opera.exe", "vivaldi.exe", "thunderbird",
                      "plugin-container", "crashpad_handler", "pingsender")
| KEEP @timestamp, host.name, user.name, process.name, process.parent.name, matched, process.command_line, _id, _index, _version
```
Suppress by host and user for 12h.

## What it catches and what it doesn't
- **Caught:** a copy (`copy`, `cp`, `Copy-Item`, `esentutl /y`), a read (`cat`, `type`, `reg`), or a decrypt tool that names the store or appears by its own name.
- **Not caught here - the file is opened by API, not named on the command line:** SharpChrome/HackBrowserData reading the DB directly when run under a generic name, or a custom stealer. The tool names above catch the common ones; **B08** (credential stores) and **23**/CS18 (tool names) back this up. FDR has no cheap generic file-read event, so the command line is the practical signal.
- **Cookies / session tokens** (the other lateral-movement path) aren't in the core set to keep it high-fidelity. To add them, put `cookies\.sqlite` and `[\\\/]cookies\b` in the regex - but baseline first, more software touches cookies.

## Before turning it on
Run it over 30 days. The legitimate hitters are backup, sync, migration and some security tooling that copies profiles - exclude those as host + process pairs, not by dropping a file from the regex. The browser exclusion is by image path, so a tool renamed to `chrome.exe` but running from the wrong folder still needs that pair added.

## When it fires
`Match` is the file or tool, `process.name`/`ImageFileName` what ran (a `Temp`, `Downloads`, `/tmp` path is a bad sign), `ParentBaseFileName` what launched it (a shell under a web worker is 13's territory), the command line where the store was read from and written to. Browser passwords are reused against internal systems - treat them as compromised and check what the host and account reached next (16, 24, B04). The key DB (`key4.db`) taken with `logins.json` means the passwords can be decrypted offline.
