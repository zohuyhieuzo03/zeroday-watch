"""Fetch sources, label items, merge into docs/feed.json and docs/feed.xml."""
import json
import os
import sys
from datetime import datetime, timezone
from email.utils import format_datetime
from xml.sax.saxutils import escape

from . import classify, feeds, judge, sources, topics, xsource

DOCS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs")
FEED_JSON = os.path.join(DOCS, "feed.json")
FEED_XML = os.path.join(DOCS, "feed.xml")
KEEP = 3000
RSS_LABELS = {"kev_exploited", "zero_day_reported", "exploited_reported"}


def norm_time(iso):
    """Normalise any ISO timestamp to UTC 'YYYY-MM-DDTHH:MM:SSZ' so strings sort."""
    try:
        d = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=timezone.utc)
        return d.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, AttributeError):
        return None


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_existing():
    try:
        with open(FEED_JSON) as f:
            return {i["id"]: i for i in json.load(f)["items"]}
    except (OSError, ValueError, KeyError):
        return {}


def merge(existing, fresh, ts):
    for item in fresh:
        old = existing.get(item["id"])
        if old is None:
            item["first_seen"] = norm_time(item.get("created")) or ts
            item["label_history"] = [{"at": ts, "label": item["label"]}]
            existing[item["id"]] = item
            continue
        old.update(
            {k: item[k] for k in ("points", "comments", "cves", "kev", "title") + (("severity",) if "severity" in item else ())}
        )
        if old["label"] != item["label"]:
            old["label"] = item["label"]
            old["label_history"].append({"at": ts, "label": item["label"]})
    items = sorted(existing.values(), key=lambda i: i["first_seen"], reverse=True)
    return items[:KEEP]


# Everything else is first-party data or ID-only, and is never reclassified from a title.
FIRST_PARTY = ("cisa-kev", "nodejs", "gitlab", "github-advisory", "github-poc", "tailscale", "x")


def reclassify(existing, kev, ts):
    """Re-run the rules on stored forum items so a rule change also fixes old labels."""
    for key in list(existing):
        item = existing[key]
        if item["source"] in FIRST_PARTY:
            continue
        c = classify.classify(item, kev)
        if c is None:
            del existing[key]
        elif c["label"] != item["label"]:
            item["label"] = c["label"]
            item["label_history"].append({"at": ts, "label": c["label"]})
        if c is not None:
            item["cves"], item["kev"] = c["cves"], c["kev"]
    return existing


def write_rss(items, ts):
    rows = []
    for i in items:
        if i["label"] not in RSS_LABELS:
            continue
        desc = "[%s] %s %s" % (i["label"], " ".join(i["cves"]), i["discussion"])
        rows.append(
            "<item><title>%s</title><link>%s</link><guid>%s</guid>"
            "<category>%s</category><description>%s</description></item>"
            % (
                escape("[%s] %s" % (i["label"], i["title"])),
                escape(i["url"] or ""),
                escape(i["id"]),
                escape(i["label"]),
                escape(desc),
            )
        )
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel>'
        "<title>zeroday-watch</title>"
        "<link>https://github.com/zohuyhieuzo03/zeroday-watch</link>"
        "<description>Forum signals about exploited vulnerabilities, labelled by evidence.</description>"
        "<lastBuildDate>%s</lastBuildDate>%s</channel></rss>"
        % (format_datetime(datetime.now(timezone.utc)), "".join(rows))
    )
    with open(FEED_XML, "w", encoding="utf-8") as f:
        f.write(xml)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    days = int(argv[argv.index("--backfill") + 1]) if "--backfill" in argv else 0
    ts = now()
    entries = sources.fetch_kev_full()
    kev = sources.kev_dates(entries)
    if days:
        raw = sources.fetch_hn(hours=days * 24, pages=20) + sources.fetch_lobsters(pages=15)
    else:
        raw = sources.fetch_hn() + sources.fetch_lobsters()
    raw += feeds.fetch_blogs(days or 3) + feeds.fetch_bluesky(days or 3)
    fresh = [c for c in (classify.classify(i, kev) for i in raw) if c]
    fresh += sources.kev_items(entries, days or 3)
    fresh += xsource.fetch_x(kev)
    for adv in sources.fetch_vendor_advisories(days or 14) + sources.fetch_github(days or 14, pages=5 if days else 1):
        in_kev = [c for c in adv["cves"] if c in kev]
        if in_kev:
            adv["label"], adv["kev"] = "kev_exploited", in_kev
        fresh.append(adv)
    print("kev=%d raw=%d relevant=%d" % (len(kev), len(raw), len(fresh)))
    if not raw:
        print("no items fetched; leaving feed untouched")
        return 1
    items = merge(reclassify(load_existing(), kev, ts), fresh, ts)
    judge.judge_items(items, ts=ts)
    os.makedirs(DOCS, exist_ok=True)
    with open(FEED_JSON, "w", encoding="utf-8") as f:
        feed = {
            "generated": ts,
            "count": len(items),
            "topics": topics.compute(items, datetime.now(timezone.utc).timestamp()),
            "items": items,
        }
        json.dump(feed, f, indent=1, ensure_ascii=False)
    write_rss(items, ts)
    return 0


if __name__ == "__main__":
    sys.exit(main())
