#!/usr/bin/env python3
"""Build the MITRE ATT&CK coverage map from the rules' front-matter.

Outputs:
  docs/MITRE-COVERAGE.md            tactic summary, kill-chain diagram, per-technique rule list, gaps
  docs/attack-navigator-layer.json  import into https://mitre-attack.github.io/attack-navigator/
  tools/attack-coverage-map.html    standalone interactive heat map; open it in any browser
  --data <file>                     optional raw JSON behind the heat map

Usage:
  curl -sSo enterprise-attack.json \
    https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.0.json
  python3 tools/mitre_coverage.py --stix enterprise-attack.json

Revoked technique IDs in a rule (e.g. T1562.001, revoked in v19) are resolved to their
replacement and listed in the report so the rule's front-matter can be updated.
"""
import argparse
import datetime
import glob
import json
import os
import re
from collections import defaultdict

# Platforms this estate actually runs (PRE = reconnaissance and resource development). Techniques
# only for macOS, ESXi or network devices are left out of the coverage percentage.
PLATFORMS = {"Windows", "Linux", "IaaS", "SaaS", "Office Suite", "Identity Provider", "Containers", "PRE"}

# Techniques seen most often in real intrusions against a Windows / M365 / Azure estate.
# Used for the "priority gaps" list only; IDs that MITRE has revoked are resolved automatically.
PRIORITY = [
    "T1566.001", "T1566.002", "T1078.004", "T1190", "T1133", "T1199",
    "T1059.001", "T1059.003", "T1059.004", "T1047", "T1053.005", "T1569.002", "T1204.002",
    "T1547.001", "T1543.003", "T1098.001", "T1136.001", "T1505.003", "T1546.003",
    "T1068", "T1134", "T1548.002",
    "T1027", "T1036", "T1055", "T1070.001", "T1218.011", "T1564.001", "T1685",
    "T1003.001", "T1003.006", "T1558.003", "T1110.003", "T1555.003", "T1621", "T1552.001", "T1539",
    "T1087.002", "T1482", "T1018", "T1069.002", "T1083", "T1082",
    "T1021.001", "T1021.002", "T1021.006", "T1570", "T1550.002",
    "T1560.001", "T1114.002", "T1213.002", "T1005",
    "T1071.001", "T1105", "T1219", "T1572", "T1090.003",
    "T1567.002", "T1048", "T1041", "T1052.001",
    "T1486", "T1490", "T1489", "T1485",
]


def ext_id(obj):
    for r in obj.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id")
    return None


def load_attack(path):
    objs = json.load(open(path))["objects"]
    by_stix = {o["id"]: o for o in objs}
    techniques = {}
    for o in objs:
        if o["type"] == "attack-pattern":
            tid = ext_id(o)
            if tid:
                techniques.setdefault(tid, o)
    revoked_by = {}
    for o in objs:
        if o["type"] == "relationship" and o.get("relationship_type") == "revoked-by":
            src, dst = by_stix.get(o["source_ref"]), by_stix.get(o["target_ref"])
            if src and dst and ext_id(src) and ext_id(dst):
                revoked_by[ext_id(src)] = ext_id(dst)
    matrix = next(o for o in objs if o["type"] == "x-mitre-matrix")
    tactics = [by_stix[t] for t in matrix["tactic_refs"]]
    version = next((o.get("x_mitre_version") for o in objs if o["type"] == "x-mitre-collection"), "")
    return techniques, revoked_by, tactics, version


def parse_rules(rules_dir):
    rules = []
    for p in sorted(glob.glob(os.path.join(rules_dir, "*", "*.md"))):
        s = open(p, encoding="utf-8").read()
        if not s.startswith("---"):
            continue
        fm = s.split("---")[1]
        rid = re.search(r"^id:\s*(\S+)", fm, re.M)
        name = re.search(r"^name:\s*(.+)$", fm, re.M)
        sev = re.search(r"^severity:\s*(\S+)", fm, re.M)
        mitre = re.search(r"^mitre:\s*\[(.*?)\]", fm, re.M)
        if not rid:
            continue
        ids = []
        for raw in (mitre.group(1).split(",") if mitre else []):
            raw = raw.strip()
            m = re.match(r"(T\d{4})(\.\d{3})?((?:/\.\d{3})*)$", raw)
            if not m:
                continue  # "various" (vendor passthrough) or a typo
            ids.append(m.group(1) + (m.group(2) or ""))
            for extra in re.findall(r"/(\.\d{3})", m.group(3) or ""):
                ids.append(m.group(1) + extra)
        rules.append({
            "id": rid.group(1), "name": name.group(1).strip() if name else "",
            "severity": sev.group(1) if sev else "", "folder": os.path.basename(os.path.dirname(p)),
            "mitre": ids,
        })
    return rules


def resolve(tid, techniques, revoked_by):
    seen = set()
    cur = tid
    while cur in revoked_by and cur not in seen:
        seen.add(cur)
        cur = revoked_by[cur]
    t = techniques.get(cur)
    if t is None and "." in cur:  # an unknown sub-technique still credits its parent
        parent = cur.split(".")[0]
        if parent in techniques and not techniques[parent].get("revoked"):
            return parent, "unknown sub-technique, credited to parent"
    if t is None:
        return None, "unknown"
    if t.get("revoked"):
        return None, "revoked, no replacement"
    note = "revoked -> " + cur if cur != tid else ("deprecated" if t.get("x_mitre_deprecated") else "")
    return cur, note


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stix", required=True)
    ap.add_argument("--rules", default="rules")
    ap.add_argument("--md", default="docs/MITRE-COVERAGE.md")
    ap.add_argument("--layer", default="docs/attack-navigator-layer.json")
    ap.add_argument("--data", default=None)
    ap.add_argument("--html", default="tools/attack-coverage-map.html")
    ap.add_argument("--template", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                       "attack-coverage-map.template.html"))
    a = ap.parse_args()

    techniques, revoked_by, tactics, version = load_attack(a.stix)
    rules = parse_rules(a.rules)

    covered = defaultdict(set)          # resolved technique id -> rule ids
    remaps = []                         # (rule, original, resolved, note)
    problems = []
    for r in rules:
        for tid in r["mitre"]:
            new, note = resolve(tid, techniques, revoked_by)
            if new is None:
                problems.append((r["id"], tid, note))
                continue
            if note:
                remaps.append((r["id"], tid, new, note))
            covered[new].add(r["id"])

    def name(tid):
        return techniques[tid]["name"]

    def tactics_of(tid):
        return [k["phase_name"] for k in techniques[tid].get("kill_chain_phases", [])
                if k.get("kill_chain_name") == "mitre-attack"]

    def relevant(t):
        return bool(set(t.get("x_mitre_platforms", [])) & PLATFORMS)

    live = {tid: t for tid, t in techniques.items()
            if not t.get("revoked") and not t.get("x_mitre_deprecated")}
    subs_of = defaultdict(list)
    for tid in live:
        if "." in tid:
            subs_of[tid.split(".")[0]].append(tid)

    rule_by_id = {r["id"]: r for r in rules}
    matrix = []
    for tac in tactics:
        short = tac["x_mitre_shortname"]
        cells = []
        for tid, t in sorted(live.items()):
            if "." in tid or short not in tactics_of(tid) or not relevant(t):
                continue
            sub_hits = {s: sorted(covered[s]) for s in sorted(subs_of[tid])
                        if covered.get(s) and short in tactics_of(s)}
            direct = sorted(covered.get(tid, set()))
            all_rules = sorted(set(direct) | {x for v in sub_hits.values() for x in v})
            cells.append({"id": tid, "name": name(tid), "rules": all_rules, "direct": direct,
                          "subs": [{"id": s, "name": name(s), "rules": v} for s, v in sub_hits.items()]})
        cells.sort(key=lambda c: (-len(c["rules"]), c["name"]))
        n_cov = sum(1 for c in cells if c["rules"])
        matrix.append({"tactic": tac["name"], "short": short, "id": ext_id(tac),
                       "covered": n_cov, "total": len(cells),
                       "rules": sorted({x for c in cells for x in c["rules"]}), "cells": cells})

    priority = []
    for tid in PRIORITY:
        new, _ = resolve(tid, techniques, revoked_by)
        if not new:
            continue
        hit = sorted(covered.get(new, set()) | {x for s in subs_of.get(new, []) for x in covered.get(s, set())})
        priority.append({"id": new, "name": name(new), "tactics": tactics_of(new), "rules": hit})

    n_rules = len(rules)
    n_tech = len([t for t in covered if "." not in t] + [t.split(".")[0] for t in covered if "." in t])
    parents_covered = {t.split(".")[0] for t in covered}
    tactic_names = {t["x_mitre_shortname"]: t["name"] for t in tactics}

    # ---------- Navigator layer ----------
    layer_techs = []
    for tid, rids in sorted(covered.items()):
        layer_techs.append({"techniqueID": tid, "score": len(rids), "comment": ", ".join(sorted(rids)),
                            "enabled": True, "showSubtechniques": True})
    for parent in sorted(parents_covered):
        if parent not in covered:
            rids = sorted({x for s in subs_of.get(parent, []) for x in covered.get(s, set())})
            layer_techs.append({"techniqueID": parent, "score": len(rids),
                                "comment": "via sub-techniques: " + ", ".join(rids),
                                "enabled": True, "showSubtechniques": True})
    max_score = max([t["score"] for t in layer_techs] + [1])
    layer = {
        "name": "Detection library coverage",
        "versions": {"attack": str(version).split(".")[0] or "19", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"{n_rules} rules. Score = number of rules mapped to the technique. Generated by tools/mitre_coverage.py.",
        "filters": {"platforms": sorted(PLATFORMS)},
        "sorting": 3,
        "layout": {"layout": "side", "showID": True, "showName": True, "aggregateFunction": "sum"},
        "hideDisabled": False,
        "techniques": layer_techs,
        "gradient": {"colors": ["#cde2fb", "#3987e5", "#0d366b"], "minValue": 1, "maxValue": min(max_score, 8)},
        "legendItems": [],
        "metadata": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }
    os.makedirs(os.path.dirname(a.layer), exist_ok=True)
    json.dump(layer, open(a.layer, "w"), indent=1)

    # ---------- Markdown ----------
    out = []
    w = out.append
    w("# MITRE ATT&CK coverage\n")
    w(f"Generated from the rules' `mitre:` front-matter against **ATT&CK Enterprise v{version}** by "
      "`tools/mitre_coverage.py`. Re-run it after adding or changing rules. A technique counts as covered when at "
      "least one rule maps to it or to one of its sub-techniques. Percentages count only techniques that apply to "
      f"this estate's platforms ({', '.join(sorted(PLATFORMS))}).\n")
    w("Coverage means a rule *targets* the technique, not that every way of doing it is caught. "
      "Use it to find empty areas, not to claim completeness.\n")
    w(f"**{n_rules} rules · {len(parents_covered)} techniques covered** "
      f"({len(covered)} technique and sub-technique IDs).\n")
    w("For the interactive heat map, open `tools/attack-coverage-map.html` in a browser (download it from GitHub "
      "first, because GitHub shows HTML as source). It is a single self-contained file you can also share or host.\n")
    w("To see it as a heat map, import `docs/attack-navigator-layer.json` into the "
      "[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) (Open Existing Layer > Upload from local). "
      "The score is the number of rules.\n")

    w("## Kill chain at a glance\n")
    w("```mermaid")
    w("flowchart LR")
    for i, m in enumerate(matrix):
        pct = round(100 * m["covered"] / m["total"]) if m["total"] else 0
        band = "none" if m["covered"] == 0 else ("low" if pct < 15 else ("mid" if pct < 35 else "high"))
        w(f'  T{i}["{m["tactic"]}<br/>{m["covered"]}/{m["total"]} techniques · {len(m["rules"])} rules"]:::{band}')
    w("  " + " --> ".join(f"T{i}" for i in range(len(matrix))))
    w("  classDef none fill:#f3f3f1,stroke:#9b9a95,color:#52514e")
    w("  classDef low fill:#cde2fb,stroke:#3987e5,color:#0b0b0b")
    w("  classDef mid fill:#6da7ec,stroke:#256abf,color:#0b0b0b")
    w("  classDef high fill:#1c5cab,stroke:#0d366b,color:#ffffff")
    w("```\n")
    w("Shading: grey = nothing, light = under 15% of the tactic's techniques, mid = 15-35%, dark = over 35%.\n")

    w("## Coverage by tactic\n")
    w("| Tactic | Techniques covered | Share | Rules |")
    w("|---|---|---|---|")
    for m in matrix:
        pct = round(100 * m["covered"] / m["total"]) if m["total"] else 0
        bar = "█" * round(pct / 5) + "░" * (20 - round(pct / 5))
        w(f"| {m['tactic']} ({m['id']}) | {m['covered']} / {m['total']} | `{bar}` {pct}% | {len(m['rules'])} |")
    w("")

    w("## Priority techniques\n")
    w("Techniques that show up most often in real intrusions against a Windows, Microsoft 365 and Azure estate. "
      "A gap here matters more than a gap in the long tail.\n")
    w("| Technique | Tactic | Rules |")
    w("|---|---|---|")
    for p in priority:
        tl = ", ".join(tactic_names.get(t, t) for t in p["tactics"])
        rl = ", ".join(p["rules"]) if p["rules"] else "**gap**"
        w(f"| {p['id']} {p['name']} | {tl} | {rl} |")
    w("")
    gaps = [p for p in priority if not p["rules"]]
    w(f"**{len(gaps)} of {len(priority)} priority techniques have no rule.**\n")

    w("## Technique detail by tactic\n")
    for m in matrix:
        cov = [c for c in m["cells"] if c["rules"]]
        if not cov:
            continue
        w(f"### {m['tactic']}\n")
        w("| Technique | Rules | Sub-techniques covered |")
        w("|---|---|---|")
        for c in cov:
            subs = "; ".join(f"{s['id']} {s['name']} ({', '.join(s['rules'])})" for s in c["subs"]) or "-"
            w(f"| {c['id']} {c['name']} | {', '.join(c['rules'])} | {subs} |")
        w("")

    if remaps or problems:
        w("## Front-matter IDs to update\n")
        w("These rules use IDs that ATT&CK has revoked or that don't exist. They are counted under the replacement "
          "shown. Update the rule's `mitre:` line.\n")
        w("| Rule | ID in rule | Counted as |")
        w("|---|---|---|")
        for rid, old, new, note in sorted(remaps):
            if note.startswith("revoked") or "unknown" in note:
                w(f"| {rid} | {old} | {new} ({note}) |")
        for rid, old, note in sorted(problems):
            w(f"| {rid} | {old} | not counted ({note}) |")
        w("")

    w("## Every rule and its techniques\n")
    w("| Rule | Name | Techniques |")
    w("|---|---|---|")
    for r in sorted(rules, key=lambda r: (r["folder"], r["id"])):
        res = sorted({resolve(t, techniques, revoked_by)[0] or t for t in r["mitre"]})
        w(f"| {r['id']} | {r['name']} | {', '.join(res) if res else '(vendor alerts, various)'} |")
    w("")
    open(a.md, "w", encoding="utf-8").write("\n".join(out))

    payload = {"version": version, "generated": datetime.date.today().isoformat(),
               "rules": {r["id"]: {"name": r["name"], "severity": r["severity"], "folder": r["folder"]}
                         for r in rules},
               "matrix": matrix, "priority": priority,
               "summary": {"rules": n_rules, "techniques": len(parents_covered), "ids": len(covered)}}
    if a.data:
        json.dump(payload, open(a.data, "w"))
    if a.html:
        write_html(a.template, a.html, payload)

    print(f"rules={n_rules} techniques_covered={len(parents_covered)} ids={len(covered)} "
          f"remapped={len([x for x in remaps if x[3].startswith('revoked')])} problems={len(problems)}")
    for rid, old, note in problems:
        print("  problem:", rid, old, note)


def write_html(template_path, out_path, payload):
    """Embed the coverage data in the page template and wrap it as a standalone HTML document."""
    t = open(template_path, encoding="utf-8").read()
    data = json.dumps(payload, separators=(",", ":")).replace("</", "<\\/")
    t = t.replace("/*__DATA__*/null", data)
    head, body = t.split("</style>", 1)
    doc = ("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
           "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
           + head + "</style>\n</head>\n<body>\n" + body.strip() + "\n</body>\n</html>\n")
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    open(out_path, "w", encoding="utf-8").write(doc)


if __name__ == "__main__":
    main()
