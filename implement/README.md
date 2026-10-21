# Implement: detections chosen to build next

Copies of the detections picked to build next, gathered in one folder. Each file is identical to its original, and an edit to either one is copied to the other.

AD CS is kept to the three most accurate rules, in priority order: AD15 (any stolen or forged certificate being used, whatever the path), AD03 (the CA's private key backed up: a golden certificate) and AD14 (a refused request issued by an officer, ESC7). I09 and AD06 stay in the library: I09 misses the usual ESC1 path, and AD06's template and CA changes are routine PKI administration too.

| File | Detection | Group | Original |
|---|---|---|---|
| [CS17](CS17-trufflehog-secret-scan.md) | Secret scanner on a host - one process tests keys against several unrelated providers (TruffleHog, Shai-Hulud, stealers) | Secrets | `rules/07-crowdstrike-fdr/CS17-trufflehog-secret-scan.md` |
| [AD15](AD15-first-certificate-logon-for-account.md) | First certificate logon (PKINIT) for an account in 30 days - a stolen or forged certificate in use, domain controllers especially | AD CS, priority 1 | `rules/14-ad-attack/AD15-first-certificate-logon-for-account.md` |
| [AD03](AD03-ca-private-key-backup.md) | Certificate authority private key backed up or exported (golden certificate) | AD CS, priority 2 | `rules/14-ad-attack/AD03-ca-private-key-backup.md` |
| [AD14](AD14-adcs-denied-request-issued-or-subca-requested.md) | Certificate authority issued a request it had denied, or the SubCA template was requested (ESC7, officer rights abused) | AD CS, priority 3 | `rules/14-ad-attack/AD14-adcs-denied-request-issued-or-subca-requested.md` |
| [B01](B01-horizontal-network-scan.md) | Internal port or host scanning by one process (outbound TCP to many hosts or many ports) | Scanning | `rules/11-behaviour/B01-horizontal-network-scan.md` |
| [CP04](CP04-crowdstrike-rfm-or-not-reporting.md) | CrowdStrike sensor online in Reduced Functionality Mode on a host people use | Sensor health | `rules/13-controlplane/CP04-crowdstrike-rfm-or-not-reporting.md` |
| [N12](N12-imperva-php2shell-worker-crash-burst.md) | PHP2Shell exploitation at the edge (CVE-2026-109618, CVE-2026-109619) - the upload-progress field the exploit uses, POSTs crashing PHP workers, or Imperva's own verdict | PHP2Shell | `rules/06-network/N12-imperva-php2shell-worker-crash-burst.md` |

## Keeping copies and originals identical
- **In Claude Code:** the hook in `.claude/settings.json` copies an edited file over its twin after every edit.
- **By hand:** `python3 tools/sync_detection_ideas.py` syncs every pair where one side has uncommitted changes. After an edit made on GitHub, pass the file you edited: `python3 tools/sync_detection_ideas.py <file>`.
- **Check:** `python3 tools/sync_detection_ideas.py --check` fails if a copy is missing or differs from its original.
- **Adding or removing a detection:** edit the list at the top of `tools/sync_detection_ideas.py`, then run it with `--readme` to create the copy and rewrite this page.
