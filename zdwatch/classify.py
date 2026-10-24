"""Rule-based labelling. Labels describe the evidence, not the truth.

kev_exploited      CVE is in CISA KEV (exploited in the wild; KEV does not say 0-day vs n-day)
zero_day_reported  title says zero-day AND exploitation/no-patch language (a claim, unconfirmed)
exploited_reported title says exploited in the wild, no zero-day wording
public_exploit_reported  CVE in title plus "exploit"/PoC wording: exploit code exists, in-the-wild use NOT claimed
zero_day_mention   zero-day wording only (rumor / discussion)
related            has a CVE id but no exploitation signal; kept for context
None               not relevant, dropped
"""
import re

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
ZERO_DAY_RE = re.compile(r"\b(zero[- ]?days?|0[- ]?days?)\b", re.I)
EXPLOIT_RE = re.compile(
    r"(exploited in the wild|actively exploited|being exploited|exploited as|"
    r"in[- ]the[- ]wild|no patch|unpatched|unfixed)",
    re.I,
)
PUBLIC_EXPLOIT_RE = re.compile(
    r"(\bexploits?\b|proof[- ]of[- ]concept|\bpoc\b|weaponi[sz]ed)", re.I
)


def classify(item, kev):
    text = item["title"]
    cves = sorted({c.upper() for c in CVE_RE.findall(text)})
    in_kev = [c for c in cves if c in kev]
    zero = bool(ZERO_DAY_RE.search(text))
    exploit = bool(EXPLOIT_RE.search(text))

    if in_kev:
        label = "kev_exploited"
    elif zero and exploit:
        label = "zero_day_reported"
    elif exploit and cves:
        label = "exploited_reported"
    elif cves and PUBLIC_EXPLOIT_RE.search(text):
        label = "public_exploit_reported"
    elif zero:
        label = "zero_day_mention"
    elif cves:
        label = "related"
    else:
        return None

    out = dict(item)
    out.update({"label": label, "cves": cves, "kev": in_kev})
    return out
