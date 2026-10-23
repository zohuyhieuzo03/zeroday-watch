import json
import os
import unittest

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
        os.environ["ZDW_MODELS"] = "a,b"
        os.environ["ZDW_MAX_LLM_ITEMS"] = "2"

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

    def test_low_confidence_is_unclear(self):
        items = [item()]
        self.run_with({"a": resp("zero_day", 0.3, 0.9), "b": resp("zero_day", 0.9, 0.9)}, items)
        self.assertEqual(items[0]["llm"]["consensus"], "unclear")

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
