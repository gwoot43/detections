#!/usr/bin/env python3
"""Check detections against docs/DETECTION-STRUCTURE-ESQL.md and docs/DETECTION-STRUCTURE-CQL.md.

Each check is one of the standards' "reject the draft if" criteria that can be tested from the query text.
The rest (null grouping keys, events linked by name, lookback shorter than the logic) need a person.

  python3 tools/lint_detections.py                 summary of every rule
  python3 tools/lint_detections.py -v              every finding, per rule
  python3 tools/lint_detections.py FILE... -v      only these files
  python3 tools/lint_detections.py --check CODE    exit 1 if any rule has that finding (for CI)
"""
import glob
import os
import re
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CHECKS = {
    # ES|QL
    "E-GATE-FUNC": "a function or cast wraps a field in the gate",
    "E-GATE-WILDCARD": "leading-wildcard LIKE or RLIKE in the gate without a justifying comment",
    "E-VALUES": "VALUES() on a high-cardinality field, not bounded with MV_SLICE",
    "E-STATS": "a second STATS without a comment justifying it",
    "E-THRESHOLD": "a threshold with no recorded source (no 'baseline' or 'source' comment)",
    "E-METADATA": "METADATA on an aggregating rule",
    "E-EXCLUSION": "an exclusion removes an entire host, user or address",
    # CQL / LogScale
    "C-TAG": "the query doesn't start with a tag field",
    "C-SHAPE-FIRST": "an assignment runs before the gate filters",
    "C-LIMIT": "groupBy() without an explicit limit",
    "C-CASE": "case {} without a * branch, and no comment saying it's a deliberate filter",
    "C-OUTPUT": "table(), or sort() without an explicit limit, instead of select()",
    "C-JOIN": "join() without a comment justifying it",
    "C-COLLECT": "collect() on a high-cardinality field",
    "C-THRESHOLD": "a threshold with no recorded source (no 'baseline' or 'source' comment)",
    "C-TEST-LOGIC": "AND or OR inside test() or beside a function call; pipe them (AND) or use case branches (OR)",
    "C-MATH-EXPR": "a math: function given a calculation instead of a field name; assign the calculation first",
    # rule file
    "R-SUPPRESSION": "no suppression field and duration",
}

ESQL_FUNCS = re.compile(r"\b(TO_LOWER|TO_UPPER|COALESCE|CONCAT|TO_STRING|TO_INTEGER|TO_LONG|TO_DOUBLE|LENGTH|SUBSTRING|REPLACE|SPLIT|TRIM|MV_\w+)\s*\(|::")
ESQL_HC = r"process\.command_line|process\.executable|process\.entity_id|destination\.ip|source\.ip|file\.path|file\.name|dns\.question\.name|url\.original|url\.full|url\.path|user_agent\.original|registry\.path|registry\.data\.strings"
CQL_HC = re.compile(r"\b(CommandLine|ImageFileName|TargetFileName|RemoteAddressIP4|RemoteAddressIP6|RemoteAddress|DomainName|FirstIP4Record|LocalAddressIP4)\b")
THRESHOLD_SOURCE = re.compile(r"(?i)//.*\b(baseline|source:|p9[59]|percentile)")
# a case {} used as a filter (no * branch on purpose) says so in a comment just above it
FILTER_CASE = re.compile(r"(?i)//.*(deliberately no|no \* branch|no default branch)")


def comments(text):
    return "\n".join(m.group(0) for m in re.finditer(r"//[^\n]*", text))


def strip_comments(text):
    out = []
    for line in text.split("\n"):
        if line.strip().startswith("//"):
            continue
        # a trailing comment, when the // isn't inside a string (an even number of quotes before it)
        m = re.search(r"\s//\s", line)
        if m and line[:m.start()].count('"') % 2 == 0:
            line = line[:m.start()]
        out.append(line)
    return "\n".join(out)


def balanced(text, start):
    """Text from the opening bracket at text[start] to its match."""
    pairs = {"(": ")", "{": "}", "[": "]"}
    open_c = text[start]; close_c = pairs[open_c]; depth = 0; quote = False
    for i in range(start, len(text)):
        c = text[i]
        if c == '"' and text[i - 1] != "\\":
            quote = not quote
        if quote:
            continue
        if c == open_c:
            depth += 1
        elif c == close_c:
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return text[start:]


def lint_esql(block):
    found = []
    code = strip_comments(block)
    stages = re.split(r"\n\s*\|", code)
    # the gate: the WHERE stages straight after FROM, before any other command
    gate_raw = []
    raw_stages = re.split(r"\n\s*\|", block)
    for raw, st in zip(raw_stages[1:], stages[1:]):
        if not st.strip().startswith("WHERE"):
            break
        gate_raw.append(raw)
    gate = strip_comments("\n".join(gate_raw))
    if ESQL_FUNCS.search(gate):
        found.append("E-GATE-FUNC")
    # a justifying comment counts inside the gate or on the lines just above it (they belong to the FROM stage)
    gate_and_lead = "\n".join(raw_stages[:1 + len(gate_raw)])
    if re.search(r'\bLIKE\s+"(?:"")?\*|\bRLIKE\b', gate) and not re.search(r"(?i)//.*(wildcard|regex|rlike)", gate_and_lead):
        found.append("E-GATE-WILDCARD")
    for m in re.finditer(r"([\w.@]+)\s*=\s*VALUES\(\s*(%s)\s*\)" % ESQL_HC, code):
        if not re.search(r"MV_SLICE\(\s*%s\b" % re.escape(m.group(1)), code[m.end():]):
            found.append("E-VALUES"); break
    stats = [m.start() for m in re.finditer(r"\n\s*\|\s*STATS\b", block)]
    for pos in stats[1:]:
        before = block[:pos].rstrip().split("\n")[-1].strip()
        if not before.startswith("//"):
            found.append("E-STATS"); break
    if stats:
        after = code[code.find("STATS"):]
        # a comparison against a number after the reduce, in a WHERE or a CASE, is a threshold
        if re.search(r"[<>]=?\s*-?\d", after) and not THRESHOLD_SOURCE.search(block):
            found.append("E-THRESHOLD")
        if "METADATA" in block.split("\n")[0]:
            found.append("E-METADATA")
    if re.search(r"NOT\s+(host\.id|host\.name|user\.name|user\.id)\s+IN\s*\(|\b(host\.id|host\.name|user\.name|user\.id)\s+NOT\s+IN\s*\(|NOT\s+CIDR_MATCH\(\s*source\.ip", code):
        found.append("E-EXCLUSION")
    return found


def lint_cql(block):
    found = []
    code = strip_comments(block)
    lines = [l.strip() for l in code.split("\n") if l.strip()]
    first = lines[0] if lines else ""
    if not (first.startswith("#") or first.startswith("(#") or first.startswith("defineTable(")):
        found.append("C-TAG")
    # the stage after the scope: an assignment before any filter
    stages = [s.strip() for s in re.split(r"\n\s*\|", code) if s.strip()]
    if len(stages) > 1 and re.match(r"^[\w.]+\s*:=", stages[1]):
        found.append("C-SHAPE-FIRST")
    for m in re.finditer(r"\bgroupBy\(", code):
        if "limit=" not in balanced(code, m.end() - 1):
            found.append("C-LIMIT"); break
    # the comment lines directly above each case, in the raw block, in the same order as the cases in the code
    raw_lines = block.split("\n")
    marked = []
    for i, l in enumerate(raw_lines):
        if re.search(r"\bcase\s*\{", l) and not l.strip().startswith("//"):
            j = i - 1
            while j >= 0 and raw_lines[j].strip().startswith("//"):
                j -= 1
            marked.append(any(FILTER_CASE.search(c) for c in raw_lines[j + 1:i]))
    for n, m in enumerate(re.finditer(r"\bcase\s*\{", code)):
        if n < len(marked) and marked[n]:
            continue
        body = balanced(code, m.end() - 1)
        # strip nested blocks so only this case's own branches are checked
        inner = body[1:-1]
        while True:
            n = re.search(r"\{", inner)
            if not n:
                break
            inner = inner[:n.start()] + inner[n.start() + len(balanced(inner, n.start())):]
        if not re.search(r"(^|[;\s])\*\s*(;|\||$)", inner):
            found.append("C-CASE"); break
    if re.search(r"\|\s*table\(", code) or any("limit=" not in balanced(code, m.end() - 1)
                                                for m in re.finditer(r"\|\s*sort\(", code)):
        found.append("C-OUTPUT")
    if re.search(r"\bjoin\(", code) and not re.search(r"(?i)//.*\bjoin\b", block):
        found.append("C-JOIN")
    for m in re.finditer(r"\bcollect\(", code):
        if CQL_HC.search(balanced(code, m.end() - 1)):
            found.append("C-COLLECT"); break
    if "groupBy(" in code and re.search(r"[<>]=?\s*-?\d", code[code.find("groupBy("):]) \
            and not THRESHOLD_SOURCE.search(block):
        found.append("C-THRESHOLD")
    if re.search(r"\bmath:\w+\([^)]*[-+*/]", code):
        found.append("C-MATH-EXPR")
    # test() sharing a stage with another filter by spaces alone (an implicit AND beside a function call)
    for stage in re.split(r"\|", code):
        st = re.sub(r"/(?:\\.|[^/\n])*/[a-zA-Z]*", " RE ", stage)
        st = re.sub(r'"(?:\\.|[^"])*"', " S ", st)
        t = re.sub(r"\btest\([^)]*\)", "T", st)
        if "T" in t.split() and re.search(r"(\w+!?=\s*\S+|RE)\s+.*\bT\b|\bT\b\s+.*(\w+!?=|RE)", t):
            found.append("C-TEST-LOGIC"); break
    # AND / OR inside test(), or joining a function call to another condition
    for m in re.finditer(r"\btest\(", code):
        if re.search(r"\b(AND|OR|and|or)\b", balanced(code, m.end() - 1)):
            found.append("C-TEST-LOGIC"); break
    else:
        for stage in re.split(r"\n\s*\|", code):
            flat = re.sub(r"/(?:\\.|[^/\n])*/[a-zA-Z]*", "", stage)  # drop regex literals, which may hold ( and |
            flat = re.sub(r'"(?:\\.|[^"])*"', '""', flat)
            if re.search(r"\b(AND|OR|and|or)\b", flat) and re.search(r"\b(test|in|cidr|match|regex)\(", flat) \
                    and not re.match(r"\s*case\s*\{", flat):
                found.append("C-TEST-LOGIC"); break
    return found


def lint_file(path):
    s = open(path, encoding="utf-8").read()
    found = []
    fm = s.split("---")[1] if s.startswith("---") else ""
    if fm and not re.search(r"suppression:\s*\n\s+fields:\s*\[[^\]]+\]\s*\n\s+duration:\s*\S+", fm):
        found.append(("R-SUPPRESSION", 0))
    for i, m in enumerate(re.finditer(r"```esql\n(.*?)```", s, re.S)):
        found += [(c, i) for c in lint_esql(m.group(1))]
    for i, m in enumerate(re.finditer(r"```logscale\n(.*?)```", s, re.S)):
        found += [(c, i) for c in lint_cql(m.group(1))]
    return found


def main(argv):
    verbose = "-v" in argv
    check = argv[argv.index("--check") + 1] if "--check" in argv else None
    files = [a for a in argv if a.endswith(".md")] or sorted(glob.glob(os.path.join(ROOT, "rules", "*", "*.md")))
    files = [f for f in files if os.path.basename(f) != "README.md"]
    totals = Counter(); per_rule = {}
    for f in files:
        found = lint_file(f)
        per_rule[f] = found
        totals.update({c for c, _ in found})
    if verbose:
        for f, found in per_rule.items():
            if found:
                print(os.path.relpath(f, ROOT))
                for code, n in sorted(set(found)):
                    print(f"    {code:15s} block {n + 1}: {CHECKS[code]}")
    clean = sum(1 for v in per_rule.values() if not v)
    print(f"\n{len(files)} rules, {clean} with no findings. Rules with each finding:")
    for code in CHECKS:
        if totals[code]:
            print(f"  {code:15s} {totals[code]:4d}  {CHECKS[code]}")
    if check:
        return 1 if totals[check] else 0
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
