"""Fetchers for public sources. Only metadata (title, link, counters) is kept."""
import html
import json
import re
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import urllib.parse

UA = "zeroday-watch/0.1 (+https://github.com/zohuyhieuzo03/zeroday-watch)"
KEV_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/main/"
    "known_exploited_vulnerabilities.json"
)
HN_QUERIES = ["0day", "zero-day", "exploited in the wild", "CVE-2026", "actively exploited", "exploit", "RCE",
              "vulnerability", "vuln", "CVE", "critical patch", "security release", "remote code execution", "CVSS"]
LOBSTERS_URL = "https://lobste.rs/t/security%s.json"


def _open(url, timeout):
    """GET with 3 attempts; transient TLS/DNS hiccups are common on CI and laptops."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    for attempt in range(3):
        try:
            return urllib.request.urlopen(req, timeout=timeout).read()
        except urllib.error.HTTPError:
            raise  # a real HTTP answer will not change on retry
        except OSError:
            if attempt == 2:
                raise
            time.sleep(2 * (attempt + 1))


def _get_json(url):
    return json.loads(_open(url, 30))


def fetch_kev_full():
    """Return the raw KEV entries (CISA catalog, GitHub mirror)."""
    return _get_json(KEV_URL).get("vulnerabilities", [])


def kev_dates(entries):
    return {v["cveID"]: v.get("dateAdded", "") for v in entries}


def kev_items(entries, days):
    """KEV additions from the last `days` days as feed items (primary source)."""
    cutoff = time.strftime("%Y-%m-%d", time.gmtime(time.time() - days * 86400))
    out = []
    for v in entries:
        added = v.get("dateAdded", "")
        if added < cutoff:
            continue
        cve = v["cveID"]
        out.append(
            {
                "id": "kev:" + cve,
                "source": "cisa-kev",
                "title": "%s: %s %s - %s"
                % (cve, v.get("vendorProject", ""), v.get("product", ""), v.get("vulnerabilityName", "")),
                "url": "https://nvd.nist.gov/vuln/detail/" + cve,
                "discussion": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                "points": 0,
                "comments": 0,
                "created": added + "T00:00:00Z",
                "label": "kev_exploited",
                "cves": [cve],
                "kev": [cve],
            }
        )
    return out


def fetch_hn(hours=48, pages=1):
    since = int(time.time()) - hours * 3600
    seen = {}
    for q, page in [(q, p) for q in HN_QUERIES for p in range(pages)]:
        params = urllib.parse.urlencode(
            {
                "query": q,
                "tags": "story",
                "numericFilters": "created_at_i>%d" % since,
                "hitsPerPage": 50,
                "page": page,
            }
        )
        try:
            hits = _get_json("https://hn.algolia.com/api/v1/search_by_date?" + params)["hits"]
        except Exception as exc:  # one failing query must not sink the run
            print("hn query %r page %d failed: %s" % (q, page, exc))
            continue
        for h in hits:
            oid = h["objectID"]
            seen[oid] = {
                "id": "hn:" + oid,
                "source": "hackernews",
                "title": h.get("title") or "",
                "url": h.get("url") or "https://news.ycombinator.com/item?id=" + oid,
                "discussion": "https://news.ycombinator.com/item?id=" + oid,
                "points": h.get("points") or 0,
                "comments": h.get("num_comments") or 0,
                "created": h.get("created_at"),
            }
    return list(seen.values())


def fetch_lobsters(pages=1):
    out = {}
    for url in [LOBSTERS_URL % ("" if n == 0 else "/page/%d" % (n + 1)) for n in range(pages)]:
        try:
            stories = _get_json(url)
        except Exception as exc:
            print("lobsters %s failed: %s" % (url, exc))
            continue
        for s in stories:
            sid = s["short_id"]
            out[sid] = {
                "id": "lobsters:" + sid,
                "source": "lobsters",
                "title": s.get("title") or "",
                "url": s.get("url") or s.get("comments_url"),
                "discussion": s.get("comments_url"),
                "points": s.get("score") or 0,
                "comments": s.get("comment_count") or 0,
                "created": s.get("created_at"),
            }
    return list(out.values())


NODE_FEED = "https://nodejs.org/en/feed/vulnerability.xml"
GITLAB_FEED = "https://about.gitlab.com/security-releases.xml"
CVE_FIND = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
ATOM = "{http://www.w3.org/2005/Atom}"


def _get_text(url, timeout=120):
    return _open(url, timeout).decode("utf-8", "replace")


def _iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _advisory(source, key, title, url, created, cves, severity):
    return {
        "id": "%s:%s" % (source, key),
        "source": source,
        "title": title,
        "url": url,
        "discussion": url,
        "points": 0,
        "comments": 0,
        "created": created,
        "label": "vendor_advisory",
        "cves": sorted({c.upper() for c in cves})[:40],
        "kev": [],
        "severity": severity,
    }


def fetch_node_advisories(days):
    """Node.js security releases (official vulnerability feed + each post's CVE list)."""
    cutoff = time.time() - days * 86400
    out = []
    for it in ET.fromstring(_get_text(NODE_FEED)).findall("./channel/item"):
        when = parsedate_to_datetime(it.findtext("pubDate"))
        if when.timestamp() < cutoff:
            continue
        link = it.findtext("link")
        try:
            page = _get_text(link, timeout=30)
        except Exception as exc:
            print("node advisory %s failed: %s" % (link, exc))
            continue
        text = html.unescape(re.sub(r"<[^>]+>", " ", re.sub(r"<script.*?</script>|<style.*?</style>", "", page, flags=re.S)))
        m = re.search(r"highest severity issue fixed in this release is (\w+)", text, re.I)
        out.append(_advisory("nodejs", link.rstrip("/").rsplit("/", 1)[-1], "Node.js: " + it.findtext("title"),
                             link, _iso(when), CVE_FIND.findall(text), m.group(1).lower() if m else None))
    return out


def fetch_gitlab_advisories(days):
    """GitLab patch releases (security-releases Atom feed); "Critical" is in the title."""
    cutoff = time.time() - days * 86400
    out = []
    for e in ET.fromstring(_get_text(GITLAB_FEED)).findall(ATOM + "entry"):
        when = datetime.fromisoformat((e.findtext(ATOM + "published") or "").replace("Z", "+00:00"))
        if when.timestamp() < cutoff:
            continue
        title = e.findtext(ATOM + "title") or ""
        link = e.find(ATOM + "link").attrib.get("href")
        sev = "critical" if title.lower().startswith("gitlab critical") else None
        out.append(_advisory("gitlab", link.rstrip("/").rsplit("/", 1)[-1], title, link, _iso(when),
                             CVE_FIND.findall(e.findtext(ATOM + "content") or ""), sev))
    return out


def fetch_vendor_advisories(days):
    out = []
    for fn in (fetch_node_advisories, fetch_gitlab_advisories):
        try:
            out += fn(days)
        except Exception as exc:  # a broken vendor feed must not sink the run
            print("%s failed: %s" % (fn.__name__, exc))
    return out
