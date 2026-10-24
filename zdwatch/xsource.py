"""X (Twitter) via the official API v2, IDs only. Skipped unless X_BEARER_TOKEN is set.

X's developer terms let a third party redistribute Post IDs, not content. So post text
lives in memory only: it is classified, CVE ids are extracted, then it is dropped. What
leaves this module is the post id/link, our own label, and a neutral placeholder title.
Never print post text: Actions logs are public.
"""
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

from . import classify, feeds

API = "https://api.x.com/2"
UA = "zeroday-watch (+https://github.com/zohuyhieuzo03/zeroday-watch)"
STATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "state", "x_state.json")
QUERY = '("zero-day" OR 0day OR "exploited in the wild" OR "actively exploited") -is:retweet lang:en'
STOP = (401, 402, 403, 429)  # stop the source for this run


class XStop(Exception):
    pass


def load_state():
    try:
        with open(STATE) as f:
            s = json.load(f)
    except (OSError, ValueError):
        s = {}
    s.setdefault("users", {})
    return s


def save_state(state):
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    with open(STATE, "w") as f:
        json.dump(state, f, indent=1, sort_keys=True)


def _get(path, params, token):
    req = urllib.request.Request(
        API + path + "?" + urllib.parse.urlencode(params),
        headers={"Authorization": "Bearer " + token, "User-Agent": UA},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.load(r)
    except urllib.error.HTTPError as exc:
        if exc.code in STOP:
            raise XStop("HTTP %d" % exc.code)
        raise


def to_item(post, kev):
    """Classify in memory; return an ID-only feed item or None. `post['text']` is never stored."""
    c = classify.classify({"title": post["text"]}, kev)
    if not c or c["label"] in ("related", "security_news"):
        return None  # weak signals are not worth a billed read's place in the feed
    cves = c["cves"][:5]
    return {
        "id": "x:" + post["id"], "source": "x", "url": "https://x.com/i/status/" + post["id"],
        "discussion": "https://x.com/i/status/" + post["id"],
        "title": "X post mentioning " + " ".join(cves) if cves else "X post (%s)" % c["label"],
        "points": 0, "comments": 0, "label": c["label"], "cves": cves, "kev": c["kev"],
    }


def fetch_x(kev, get=_get, state=None, save=True):
    token = os.environ.get("X_BEARER_TOKEN")
    if not token:
        print("x source skipped: X_BEARER_TOKEN not set")
        return []
    state = state if state is not None else load_state()
    budget = int(os.environ.get("ZDW_X_MAX_POSTS", "200"))  # posts read per run = cost cap
    found, read = {}, 0  # keyed by id: a post can appear in a timeline and in search
    jobs = [("/users/%s/tweets" % u, {"exclude": "replies,retweets"}, ("users", u)) for u in feeds.read_list("x_user_ids.txt")]
    jobs.append(("/tweets/search/recent", {"query": QUERY}, ("search", None)))
    try:
        for path, extra, (kind, key) in jobs:
            if read >= budget:
                break
            since = state["users"].get(key) if kind == "users" else state.get("search")
            p = dict(extra)
            p["max_results"] = 100 if since else 10  # first run small to bound cost
            if since:
                p["since_id"] = since
            p["tweet.fields"] = "created_at"  # no expansions: they would add billed objects
            data = get(path, p, token)
            posts = data.get("data", [])
            read += len(posts)
            for i in (to_item(t, kev) for t in posts):
                if i:
                    found[i["id"]] = i
            newest = data.get("meta", {}).get("newest_id")
            if newest:  # advance even for posts that did not classify, or they are re-billed
                if kind == "users":
                    state["users"][key] = newest
                else:
                    state["search"] = newest
    except XStop as exc:
        print("x source stopped: %s" % exc)
    except Exception as exc:
        print("x source failed: %s" % type(exc).__name__)  # never echo bodies
    if save:
        save_state(state)
    print("x: read %d post(s), kept %d" % (read, len(found)))
    return list(found.values())
