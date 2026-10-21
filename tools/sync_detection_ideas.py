#!/usr/bin/env python3
"""Keep detection_ideas/ identical to the rules it copies.

detection_ideas/ holds copies of the C2, tunnelling, post-exploitation and AI detections. Edit a copy or its
original and this script copies the edited file over the other. The Claude Code hook in
.claude/settings.json runs it after every edit.

  python3 tools/sync_detection_ideas.py            sync pairs where one side has uncommitted changes
  python3 tools/sync_detection_ideas.py FILE...    copy FILE (an original or a copy) over its twin
  python3 tools/sync_detection_ideas.py --check    exit 1 if a copy is missing or differs
  python3 tools/sync_detection_ideas.py --readme   create missing copies and rewrite detection_ideas/README.md
  python3 tools/sync_detection_ideas.py --hook     hook mode: reads the tool call as JSON on stdin
"""
import json
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IDEAS = "detection_ideas"

# (group, original). To add or remove a detection, edit this list and run with --readme.
SOURCES = [
    ("C2", "rules/11-behaviour/B06-c2-beaconing.md"),
    ("C2", "rules/11-behaviour/B10-zscaler-c2-beaconing.md"),
    ("C2", "rules/06-network/N07-zscaler-c2-and-malware-callback.md"),
    ("C2", "rules/04-endpoint-linux/L01-reverse-shell.md"),
    ("Tunnelling", "rules/07-crowdstrike-fdr/CS03-dns-tunnelling.md"),
    ("Tunnelling", "rules/07-crowdstrike-fdr/CS09-windows-port-forward-portproxy.md"),
    ("Tunnelling", "rules/07-crowdstrike-fdr/CS10-web-server-new-internal-admin-connection.md"),
    ("Tunnelling", "rules/07-crowdstrike-fdr/CS11-rare-program-accepting-internal-connections.md"),
    ("Tunnelling", "rules/07-crowdstrike-fdr/CS13-vscode-tunnel.md"),
    ("Tunnelling", "rules/07-crowdstrike-fdr/CS14-tunnel-service-agent.md"),
    ("Tunnelling", "rules/07-crowdstrike-fdr/CS15-admin-service-reached-from-loopback.md"),
    ("Tunnelling", "rules/07-crowdstrike-fdr/CS16-rare-program-reaches-internal-admin-services.md"),
    ("Tunnelling", "rules/04-endpoint-linux/L14-temp-or-memory-program-listening.md"),
    ("Tunnelling", "rules/06-network/N09-zscaler-tunnel-and-policy-evasion.md"),
    ("Tunnelling", "rules/03-endpoint-windows/W10-unauthorised-rmm-or-tunnel.md"),
    ("Tunnelling", "fixed-detections/01-tunnel-service-connection.md"),
    ("Tunnelling", "fixed-detections/02-dns-tunneling.md"),
    ("Post-exploitation", "rules/04-endpoint-linux/L07-defense-evasion-log-and-history-tamper.md"),
    ("Post-exploitation", "rules/04-endpoint-linux/L13-rare-setuid-root-program.md"),
    ("Post-exploitation", "rules/04-endpoint-linux/L15-passwordless-sudo-grant-written.md"),
    ("Post-exploitation", "rules/07-crowdstrike-fdr/CS17-trufflehog-secret-scan.md"),
    ("Webshell", "rules/06-network/N11-imperva-new-script-page-posted-by-few-clients.md"),
    ("AI", "rules/17-ai-detections/AI01-host-starts-calling-llm-api.md"),
    ("AI", "rules/17-ai-detections/AI02-ai-coding-agent-run-unattended-with-approvals-off.md"),
    ("AI", "rules/17-ai-detections/AI03-m365-copilot-prompt-injection-or-jailbreak.md"),
    ("AI", "rules/17-ai-detections/AI04-azure-openai-keys-or-content-filter-new-identity.md"),
    ("AI", "rules/17-ai-detections/AI05-download-after-ai-assistant-link.md"),
    ("AI", "rules/17-ai-detections/AI06-code-editor-looks-up-rare-domain.md"),
    ("AI", "rules/17-ai-detections/AI07-ai-agent-or-editor-runs-download-and-execute.md"),
    ("AI", "rules/17-ai-detections/AI08-prompt-for-an-ai-model-in-command-line-or-script.md"),
    ("AI", "rules/17-ai-detections/AI09-copilot-studio-agent-published-or-auth-changed-by-new-maker.md"),
    ("AI", "rules/17-ai-detections/AI10-defender-for-cloud-ai-threat-alerts.md"),
    ("AI", "rules/17-ai-detections/AI11-first-large-upload-to-rarely-used-ai-app.md"),
]


def copy_of(original):
    prefix = "fixed-" if original.startswith("fixed-detections/") else ""
    return f"{IDEAS}/{prefix}{os.path.basename(original)}"


PAIRS = [(o, copy_of(o)) for _, o in SOURCES]
TWIN = {**{o: c for o, c in PAIRS}, **{c: o for o, c in PAIRS}}


def path(rel):
    return os.path.join(ROOT, rel)


def same(a, b):
    if not (os.path.exists(path(a)) and os.path.exists(path(b))):
        return False
    with open(path(a), "rb") as fa, open(path(b), "rb") as fb:
        return fa.read() == fb.read()


def copy(src, dst, log):
    if os.path.exists(path(src)) and not same(src, dst):
        os.makedirs(os.path.dirname(path(dst)), exist_ok=True)
        shutil.copyfile(path(src), path(dst))
        log.append(f"copied {src} -> {dst}")


def uncommitted():
    out = subprocess.run(["git", "-C", ROOT, "status", "--porcelain", "-z", "--untracked-files=all"], capture_output=True, text=True).stdout
    return {e[3:] for e in out.split("\0") if len(e) > 3 and e[2] == " "}


def sync_files(files, log):
    for f in files:
        rel = os.path.relpath(os.path.abspath(f), ROOT)
        if rel in TWIN:
            copy(rel, TWIN[rel], log)


def sync_uncommitted(log):
    """A pair where one side has uncommitted changes takes that side. If both do, the newer file wins."""
    changed = uncommitted()
    for o, c in PAIRS:
        if not os.path.exists(path(c)):
            copy(o, c, log)
        elif same(o, c):
            continue
        elif o in changed and c not in changed:
            copy(o, c, log)
        elif c in changed and o not in changed:
            copy(c, o, log)
        elif o in changed:
            newer, older = (o, c) if os.path.getmtime(path(o)) >= os.path.getmtime(path(c)) else (c, o)
            copy(newer, older, log)
        else:
            log.append(f"differs with no uncommitted change, not synced: {o} / {c} (run with the file you changed)")


def check():
    bad = [f"{o} / {c}" for o, c in PAIRS if not same(o, c)]
    for b in bad:
        print(f"out of sync or missing: {b}")
    return 1 if bad else 0


def title(original):
    text = open(path(original), encoding="utf-8").read()
    m = re.search(r"^name: (.+)$", text, re.M) or re.search(r"^# (.+)$", text, re.M)
    return m.group(1).strip() if m else os.path.basename(original)


def readme(log):
    for o, c in PAIRS:
        if not os.path.exists(path(c)):
            copy(o, c, log)
    rows = []
    for (group, o), (_, c) in zip(SOURCES, PAIRS):
        name = os.path.basename(c)
        label = "Fixed " + name.split("-")[1] if name.startswith("fixed-") else name.split("-")[0]
        rows.append(f"| [{label}]({name}) | {title(o)} | {group} | `{o}` |")
    body = "\n".join([
        "# Detection ideas: C2, tunnelling, post-exploitation and AI",
        "",
        "Copies of the library's C2, tunnelling, post-exploitation and AI detections, gathered in one folder. Each file is identical to its original, and an edit to either one is copied to the other.",
        "",
        "[SUMMARY.md](SUMMARY.md) says what each one covers, how it detects and how it stays quiet, with schedule, suppression and ATT&CK.",
        "",
        "| File | Detection | Group | Original |",
        "|---|---|---|---|",
        *rows,
        "",
        "## Keeping copies and originals identical",
        "- **In Claude Code:** the hook in `.claude/settings.json` copies an edited file over its twin after every edit.",
        "- **By hand:** `python3 tools/sync_detection_ideas.py` syncs every pair where one side has uncommitted changes. After an edit made on GitHub, pass the file you edited: `python3 tools/sync_detection_ideas.py <file>`.",
        "- **Check:** `python3 tools/sync_detection_ideas.py --check` fails if a copy is missing or differs from its original.",
        "- **Adding or removing a detection:** edit the list at the top of `tools/sync_detection_ideas.py`, then run it with `--readme` to create the copy and rewrite this page.",
        "",
    ])
    with open(path(f"{IDEAS}/README.md"), "w", encoding="utf-8") as f:
        f.write(body)


def hook():
    try:
        event = json.load(sys.stdin)
    except ValueError:
        event = {}
    tool_input = event.get("tool_input") or {}
    edited = tool_input.get("file_path") or tool_input.get("notebook_path")
    log = []
    if edited:
        sync_files([edited], log)
    else:
        sync_uncommitted(log)
        log = [line for line in log if line.startswith("copied")]
    if log:
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                                 "additionalContext": "detection_ideas sync: " + "; ".join(log)}}))
    return 0


def main(argv):
    if "--hook" in argv:
        return hook()
    if "--check" in argv:
        return check()
    log = []
    if "--readme" in argv:
        readme(log)
    elif argv:
        sync_files(argv, log)
    else:
        sync_uncommitted(log)
    for line in log:
        print(line)
    return check()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
