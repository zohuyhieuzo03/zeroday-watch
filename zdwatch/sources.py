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
LOBSTERS_URLS = ["https://lobste.rs/t/security.json"]


def _get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def fetch_kev():
    """Return {CVE-ID: dateAdded} from the CISA KEV catalog (GitHub mirror)."""
    data = _get_json(KEV_URL)
    return {v["cveID"]: v.get("dateAdded", "") for v in data.get("vulnerabilities", [])}


def fetch_hn(hours=48):
    since = int(time.time()) - hours * 3600
    seen = {}
    for q in HN_QUERIES:
        params = urllib.parse.urlencode(
            {
                "query": q,
                "tags": "story",
                "numericFilters": "created_at_i>%d" % since,
                "hitsPerPage": 50,
            }
        )
        try:
            hits = _get_json("https://hn.algolia.com/api/v1/search_by_date?" + params)["hits"]
        except Exception as exc:  # one failing query must not sink the run
            print("hn query %r failed: %s" % (q, exc))
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


def fetch_lobsters():
    out = {}
    for url in LOBSTERS_URLS:
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
