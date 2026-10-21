# Implement: detections chosen to build next

Copies of the detections picked to build next, gathered in one folder. Each file is identical to its original, and an edit to either one is copied to the other.

| File | Detection | Group | Original |
|---|---|---|---|
| [CS17](CS17-trufflehog-secret-scan.md) | Secret scanner on a host - one process tests keys against several unrelated providers (TruffleHog, Shai-Hulud, stealers) | Secrets | `rules/07-crowdstrike-fdr/CS17-trufflehog-secret-scan.md` |
| [AD14](AD14-adcs-denied-request-issued-or-subca-requested.md) | Certificate authority issued a request it had denied, or the SubCA template was requested (ESC7, officer rights abused) | AD CS | `rules/14-ad-attack/AD14-adcs-denied-request-issued-or-subca-requested.md` |
| [AD15](AD15-first-certificate-logon-for-account.md) | First certificate logon (PKINIT) for an account in 30 days - a stolen or forged certificate in use, domain controllers especially | AD CS | `rules/14-ad-attack/AD15-first-certificate-logon-for-account.md` |

## Keeping copies and originals identical
- **In Claude Code:** the hook in `.claude/settings.json` copies an edited file over its twin after every edit.
- **By hand:** `python3 tools/sync_detection_ideas.py` syncs every pair where one side has uncommitted changes. After an edit made on GitHub, pass the file you edited: `python3 tools/sync_detection_ideas.py <file>`.
- **Check:** `python3 tools/sync_detection_ideas.py --check` fails if a copy is missing or differs from its original.
- **Adding or removing a detection:** edit the list at the top of `tools/sync_detection_ideas.py`, then run it with `--readme` to create the copy and rewrite this page.
