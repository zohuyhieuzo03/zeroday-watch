"""Researcher blogs (RSS/Atom) and Bluesky accounts. Titles and links only are kept."""
import json
import os
import re
import time
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

from . import sources

CONFIG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config")
ATOM = "{http://www.w3.org/2005/Atom}"
BSKY = "https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed"


def read_list(name):
    try:
        with open(os.path.join(CONFIG, name)) as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except OSError:
        return []


def _when(text):
    for parse in (parsedate_to_datetime, lambda t: datetime.fromisoformat(t.replace("Z", "+00:00"))):
        try:
            d = parse(text.strip())
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError, AttributeError):
            continue
    return None


def parse_feed(xml_text, since_ts):
    """Return [(title, link, datetime)] for RSS 2.0 or Atom entries newer than since_ts."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        # Real-world feeds often carry bare "&" or control characters; repair and retry once.
        fixed = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", xml_text)
        fixed = re.sub(r"&(?!(?:amp|lt|gt|quot|apos|#\d+|#x[0-9a-fA-F]+);)", "&amp;", fixed)
        root = ET.fromstring(fixed)
    out = []
    for it in root.iter("item"):
        d = _when(it.findtext("pubDate") or it.findtext("{http://purl.org/dc/elements/1.1/}date") or "")
        out.append((it.findtext("title") or "", it.findtext("link") or "", d))
    for en in root.iter(ATOM + "entry"):
        link = ""
        for l in en.findall(ATOM + "link"):
            if l.attrib.get("rel", "alternate") == "alternate":
                link = l.attrib.get("href", "")
                break
        d = _when(en.findtext(ATOM + "published") or en.findtext(ATOM + "updated") or "")
        out.append((en.findtext(ATOM + "title") or "", link, d))
    return [(re.sub(r"\s+", " ", t).strip(), l.strip(), d) for t, l, d in out
            if t and l and d and d.timestamp() >= since_ts]


def _name(url):
    host = urllib.parse.urlparse(url).netloc.lower()
    return host[4:] if host.startswith("www.") else host


def fetch_blogs(days):
    since = time.time() - days * 86400
    items = []
    for url in read_list("blog_feeds.txt"):
        try:
            entries = parse_feed(sources._get_text(url, timeout=30), since)
        except Exception as exc:  # one dead feed must not sink the run
            print("blog feed %s failed: %s" % (url, exc))
            continue
        for title, link, d in entries:
            items.append({
                "id": "blog:" + link, "source": _name(url), "title": title, "url": link,
                "discussion": link, "points": 0, "comments": 0,
                "created": d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            })
    return items


def post_item(handle, post, since_ts):
    rec = post["post"]["record"]
    d = _when(rec.get("createdAt", ""))
    if not d or d.timestamp() < since_ts or post.get("reason"):  # skip reposts
        return None
    text = re.sub(r"\s+", " ", rec.get("text", "")).strip()
    if not text:
        return None
    rkey = post["post"]["uri"].rsplit("/", 1)[-1]
    url = "https://bsky.app/profile/%s/post/%s" % (handle, rkey)
    return {
        "id": "bsky:" + post["post"]["uri"], "source": "bluesky", "title": text[:160], "url": url,
        "discussion": url, "points": post["post"].get("likeCount", 0),
        "comments": post["post"].get("replyCount", 0),
        "created": d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def fetch_bluesky(days):
    since = time.time() - days * 86400
    items = []
    for handle in read_list("bluesky_accounts.txt"):
        qs = urllib.parse.urlencode({"actor": handle, "limit": 100, "filter": "posts_no_replies"})
        try:
            feed = sources._get_json(BSKY + "?" + qs).get("feed", [])
        except Exception as exc:
            print("bluesky %s failed: %s" % (handle, exc))
            continue
        items += [i for i in (post_item(handle, p, since) for p in feed) if i]
    return items
