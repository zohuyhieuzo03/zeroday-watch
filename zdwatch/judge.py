"""Optional LLM judge using OpenRouter's Decisions API (alpha).

Reads OPENROUTER_API_KEY from the environment; without it the judge is skipped.
Consensus: `unclear` and low-confidence answers abstain; `disputed` only when two
confident labels differ. The judge never changes the rule-based `label`. It adds an `llm` field with each
model's answer and a consensus, so a human (or a later primary-source check) decides.

Env:
  OPENROUTER_API_KEY   required to run
  ZDW_MODELS           comma list of decision models (default: two free ones)
  ZDW_MAX_LLM_ITEMS    max items judged per run (default 10; free tiers are tight)
"""
import json
import os
import urllib.error
import urllib.request

ENDPOINT = "https://openrouter.ai/api/alpha/decisions"
DEFAULT_MODELS = "inception/mercury-decide:free,baseten/mammoth-1:free"
PRIMARY_SOURCES = ("cisa-kev", "nodejs", "gitlab", "github-advisory", "github-poc")  # first-party data, nothing to judge
JUDGE_LABELS = ("zero_day", "n_day_exploited", "disclosed_unpatched", "not_exploited", "unclear")
MIN_CONFIDENCE = 0.6
# Spend the limited free quota on the claims that matter most first (sort is stable).
PRIORITY = ["zero_day_reported", "zero_day_mention", "exploited_reported", "public_exploit_reported", "kev_exploited", "related", "security_news"]

QUESTIONS = {
    "status": {
        "type": "choice",
        "instructions": (
            "Based only on the headline and metadata, what is the exploitation status "
            "of the vulnerability being discussed? Choose unclear if the headline does "
            "not say."
        ),
        "criteria": {
            "zero_day": "Exploited in the wild before a patch existed, or described as a zero-day under attack.",
            "n_day_exploited": "A patched, older vulnerability that is being exploited.",
            "disclosed_unpatched": "Publicly disclosed, no patch yet, no reported exploitation.",
            "not_exploited": "A vulnerability or advisory with no sign of exploitation.",
            "unclear": "The headline does not say, is a question, an advertisement, or is not about a specific vulnerability.",
        },
    },
    "exploited": {
        "type": "noul",
        "instructions": "Does the headline state that the vulnerability is being or was exploited in real attacks?",
        "criteria": {
            "true": "The headline says it is actively exploited, exploited in the wild, or under attack.",
            "false": "The headline does not state real-world exploitation.",
        },
    },
}


class JudgeStop(Exception):
    """Raised on errors where retrying this run is pointless (auth, quota, rate limit)."""


def build_state(item):
    return {
        "headline": item["title"],
        "source": item["source"],
        "points": item.get("points", 0),
        "comments": item.get("comments", 0),
        "cves": item.get("cves", []),
        "in_cisa_kev": bool(item.get("kev")),
    }


def call(model, item, key, post=None):
    body = json.dumps(
        {"model": model, "state": build_state(item), "questions": QUESTIONS}
    ).encode()
    if post is not None:
        return post(body)
    req = urllib.request.Request(
        ENDPOINT,
        data=body,
        headers={
            "Authorization": "Bearer " + key,
            "Content-Type": "application/json",
            "User-Agent": "zeroday-watch/0.1",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 402, 403, 429):
            raise JudgeStop("HTTP %d from %s" % (exc.code, model))
        raise


def parse(resp):
    """Pull the fields we use out of a Decisions response; None if malformed."""
    try:
        ans = resp["answers"]
        status = ans["status"]
        label = status["choice"]
        if label not in JUDGE_LABELS:
            return None
        return {
            "status": label,
            "confidence": float(status.get("confidence", 0)),
            "exploited": float(ans["exploited"]["noul"]),
        }
    except (KeyError, TypeError, ValueError):
        return None


def consensus(per_model):
    """`unclear` and low-confidence answers abstain; `disputed` only when two
    confident labels differ. Returns (label, votes) or (None, 0) with no answers."""
    usable = {m: r for m, r in per_model.items() if r}
    if not usable:
        return None, 0
    votes = [
        r["status"]
        for r in usable.values()
        if r["status"] != "unclear" and r["confidence"] >= MIN_CONFIDENCE
    ]
    if not votes:
        return "unclear", 0
    if len(set(votes)) > 1:
        return "disputed", len(votes)
    return votes[0], len(votes)


def refresh_consensus(items):
    """Recompute consensus from stored model answers (the rule may have changed)."""
    for item in items:
        llm = item.get("llm")
        if llm:
            llm["consensus"], llm["votes"] = consensus(llm["models"])


def needs_judging(item):
    if item.get("source") in PRIMARY_SOURCES:
        return False
    llm = item.get("llm")
    return not llm or llm.get("title") != item["title"]


def judge_items(items, key=None, post=None, ts=""):
    """Judge up to ZDW_MAX_LLM_ITEMS items in place. Returns how many were judged."""
    refresh_consensus(items)
    key = key or os.environ.get("OPENROUTER_API_KEY")
    if not key and post is None:
        print("llm judge skipped: OPENROUTER_API_KEY not set")
        return 0
    models = [m.strip() for m in os.environ.get("ZDW_MODELS", DEFAULT_MODELS).split(",") if m.strip()]
    limit = int(os.environ.get("ZDW_MAX_LLM_ITEMS", "10"))
    todo = [i for i in items if needs_judging(i)]
    todo.sort(key=lambda i: PRIORITY.index(i.get("label")) if i.get("label") in PRIORITY else len(PRIORITY))
    todo = todo[:limit]
    done = 0
    for item in todo:
        per_model = {}
        try:
            for model in models:
                try:
                    per_model[model] = parse(call(model, item, key, post))
                except JudgeStop:
                    raise
                except Exception as exc:  # one bad model/item must not sink the run
                    print("judge %s failed on %s: %s" % (model, item["id"], exc))
                    per_model[model] = None
        except JudgeStop as exc:
            print("llm judge stopped: %s" % exc)
            break
        label, nvotes = consensus(per_model)
        item["llm"] = {
            "title": item["title"],
            "at": ts,
            "models": per_model,
            "consensus": label,
            "votes": nvotes,
        }
        done += 1
    print("llm judged %d item(s)" % done)
    return done
