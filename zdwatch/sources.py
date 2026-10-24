"""Fetchers for public sources. Only metadata (title, link, counters) is kept."""
import json
import time
import urllib.parse
import urllib.request

UA = "zeroday-watch/0.1 (+https://github.com/zohuyhieuzo03/zeroday-watch)"
KEV_URL = (
    "https://raw.githubusercontent.com/cisagov/kev-data/main/"
    "known_exploited_vulnerabilities.json"
)
HN_QUERIES = ["0day", "zero-day", "exploited in the wild", "CVE-2026", "actively exploited"]
LOBSTERS_URL = "https://lobste.rs/t/security%s.json"


def _get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


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
