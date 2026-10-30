import json
import os
import unittest
from unittest import mock

from zdwatch import judge


def resp(label, conf, exploited):
    return {
        "answers": {
            "status": {"type": "choice", "choice": label, "confidence": conf, "probabilities": {}},
            "exploited": {"type": "noul", "noul": exploited},
        }
    }


def item(i="x"):
    return {"id": i, "title": "Chrome zero-day exploited", "source": "hackernews", "cves": [], "kev": []}


class JudgeTest(unittest.TestCase):
    def setUp(self):
        # Hermetic: a host's own ZDW_* settings (e.g. ZDW_JUDGE=claude on le11) must not leak in.
        patcher = mock.patch.dict(os.environ, {"ZDW_MODELS": "a,b", "ZDW_MAX_LLM_ITEMS": "2"})
        patcher.start()
        self.addCleanup(patcher.stop)
        for k in [k for k in os.environ if k.startswith("ZDW_") and k not in ("ZDW_MODELS", "ZDW_MAX_LLM_ITEMS")]:
            del os.environ[k]

    def run_with(self, answers, items):
        calls = []

        def post(body):
            calls.append(json.loads(body)["model"])
            r = answers[calls[-1]]
            if isinstance(r, Exception):
                raise r
            return r

        n = judge.judge_items(items, key="k", post=post, ts="t")
        return n, calls

    def test_parse_rejects_unknown_label(self):
        self.assertIsNone(judge.parse(resp("bogus", 0.9, 0.9)))
        self.assertIsNone(judge.parse({}))

    def test_agreement_gives_label(self):
        items = [item()]
        self.run_with({"a": resp("zero_day", 0.9, 0.9), "b": resp("zero_day", 0.8, 0.7)}, items)
        self.assertEqual(items[0]["llm"]["consensus"], "zero_day")

    def test_disagreement_is_disputed(self):
        items = [item()]
        self.run_with({"a": resp("zero_day", 0.9, 0.9), "b": resp("n_day_exploited", 0.9, 0.9)}, items)
        self.assertEqual(items[0]["llm"]["consensus"], "disputed")

    def test_unclear_abstains(self):
        items = [item()]
        self.run_with({"a": resp("unclear", 0.9, 0.0), "b": resp("not_exploited", 0.9, 0.0)}, items)
        self.assertEqual(items[0]["llm"]["consensus"], "not_exploited")
        self.assertEqual(items[0]["llm"]["votes"], 1)

    def test_low_confidence_abstains(self):
        items = [item()]
        self.run_with({"a": resp("zero_day", 0.3, 0.9), "b": resp("zero_day", 0.9, 0.9)}, items)
        self.assertEqual(items[0]["llm"]["consensus"], "zero_day")
        self.assertEqual(items[0]["llm"]["votes"], 1)

    def test_all_abstain_is_unclear(self):
        items = [item()]
        self.run_with({"a": resp("zero_day", 0.3, 0.9), "b": resp("unclear", 0.9, 0.0)}, items)
        self.assertEqual(items[0]["llm"]["consensus"], "unclear")
        self.assertEqual(items[0]["llm"]["votes"], 0)

    def test_failed_model_does_not_dispute(self):
        items = [item()]
        self.run_with({"a": None, "b": resp("zero_day", 0.9, 0.9)}, items)
        self.assertEqual(items[0]["llm"]["consensus"], "zero_day")

    def test_refresh_recomputes_old_consensus(self):
        old = item()
        old["llm"] = {
            "title": old["title"],
            "consensus": "disputed",
            "models": {"a": {"status": "unclear", "confidence": 0.9, "exploited": 0.0},
                       "b": {"status": "not_exploited", "confidence": 0.9, "exploited": 0.0}},
        }
        judge.refresh_consensus([old])
        self.assertEqual(old["llm"]["consensus"], "not_exploited")

    def test_limit_and_skip_already_judged(self):
        items = [item("1"), item("2"), item("3")]
        ok = {"a": resp("zero_day", 0.9, 0.9), "b": resp("zero_day", 0.9, 0.9)}
        n, _ = self.run_with(ok, items)
        self.assertEqual(n, 2)
        n, _ = self.run_with(ok, items)  # only the third remains
        self.assertEqual(n, 1)

    def test_rate_limit_stops_run_without_marking_item(self):
        items = [item("1"), item("2")]
        n, calls = self.run_with({"a": judge.JudgeStop("429"), "b": None}, items)
        self.assertEqual(n, 0)
        self.assertEqual(calls, ["a"])
        self.assertNotIn("llm", items[0])

    def test_skipped_without_key(self):
        os.environ.pop("OPENROUTER_API_KEY", None)
        self.assertEqual(judge.judge_items([item()]), 0)


if __name__ == "__main__":
    unittest.main()
