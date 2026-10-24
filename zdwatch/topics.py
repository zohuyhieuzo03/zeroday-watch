"""Group recent items into trending topics without any model.

An item is assigned to the rarest shared token in its headline (a CVE id or a
distinctive word such as a campaign name), so "php2shell" is chosen over "php".
A topic needs at least MIN_THREADS items inside the window.
"""
import math
import re
from collections import Counter, defaultdict
from datetime import datetime

MIN_THREADS = 3
TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9.+#_-]*[a-z0-9]")
STOP = set(
    """
    vulnerability vulnerabilities vulnerable security critical patch patches patched release released releases
    remote code execution exploit exploits exploited exploiting update updates found vuln vulns flaw flaws issue
    issues using with from that this have been your what when about into after over more than they their there
    which would could should attack attacks attackers malware hackers hacker hacked breach data zero-day zeroday
    actively severity high medium low major serious public proof concept advisory advisories cves bug bugs fixes
    fixed fix new newly warn warns warning discloses disclosed says show news affected allows allow need needs
    just only some very also cvss years year week days last first second third open source tool tools script
    check scanner small notes config audit analysis report reports user users software server servers system
    systems access service services version versions install latest latest-version out all how why who can now
    tell upcoming being compromised disclosure global affects affecting target targets targeted targeting
    again still while where between through against under without within across before during every other
    people company companies research researchers million billion memory exploitation
    january february march april june july august september october november december
    """.split()
)


def tokens(title):
    out = set()
    for t in TOKEN_RE.findall(title.lower()):
        t = t.strip(".-+_#")
        if len(t) < 4 or re.fullmatch(r"[\d.]+", t) or t in STOP:
            continue
        out.add(t)
    return out


def _ts(iso):
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


def _surface(token, titles):
    for ti in titles:
        m = re.search(re.escape(token), ti, re.I)
        if m:
            return m.group(0)
    return token


def _name_like(token):
    return token.startswith("cve-") or (any(c.isdigit() for c in token) and any(c.isalpha() for c in token))


def compute(items, now_ts, days=7, limit=25):
    cutoff = now_ts - days * 86400
    pool = [i for i in items if i.get("source") != "cisa-kev" and _ts(i["first_seen"]) >= cutoff]
    toks = {i["id"]: tokens(i["title"]) | {c.lower() for c in i.get("cves", [])} for i in pool}
    df = Counter(t for ts in toks.values() for t in ts)
    # A token may name a topic only if it looks like a name (CVE id, or letters+digits such
    # as "php2shell") or shows up in at least one item that already has a concrete signal.
    strong = {t for i in pool if i["label"] != "security_news" for t in toks[i["id"]]}
    cand = {t for t, n in df.items() if n >= MIN_THREADS and (_name_like(t) or t in strong)}
    groups = defaultdict(list)
    for i in pool:
        mine = [t for t in toks[i["id"]] if t in cand]
        if mine:
            groups[min(mine, key=lambda t: (df[t], -len(t)))].append(i)
    raw = [(tok, ms) for tok, ms in groups.items() if len(ms) >= MIN_THREADS]
    # Merge groups that share a CVE (e.g. "php2shell" and the CVE ids its threads cite).
    raw.sort(key=lambda g: len(g[1]), reverse=True)
    merged = []  # [name_token, {id: item}, cve_set]
    for tok, ms in raw:
        cves = {c for m in ms for c in m.get("cves", [])}
        hit = next((g for g in merged if g[2] & cves), None)
        if hit:
            hit[1].update({m["id"]: m for m in ms})
            hit[2].update(cves)
        else:
            merged.append([tok, {m["id"]: m for m in ms}, set(cves)])
    topics = []
    for tok, by_id, _ in merged:
        members = sorted(by_id.values(), key=lambda i: (i.get("points", 0), i["first_seen"]), reverse=True)
        if len(members) < MIN_THREADS:
            continue
        cves = Counter(c for m in members for c in m.get("cves", []))
        topics.append(
            {
                "name": _surface(tok, [m["title"] for m in members]),
                "threads": len(members),
                "points": sum(m.get("points", 0) for m in members),
                "kev": any(m.get("kev") for m in members),
                "vendor": any(m["label"] == "vendor_advisory" for m in members),
                "cves": [c for c, _ in cves.most_common(4)],
                "last_seen": max(m["first_seen"] for m in members),
                "items": [m["id"] for m in members][:25],
            }
        )
    topics.sort(key=lambda t: (t["threads"] + math.log10(1 + t["points"]), t["last_seen"]), reverse=True)
    return topics[:limit]
