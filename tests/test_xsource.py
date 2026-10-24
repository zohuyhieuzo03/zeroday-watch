import os
import unittest
from unittest import mock

from zdwatch import xsource

KEV = {"CVE-2026-1234": "2026-10-01"}


class XSourceTest(unittest.TestCase):
    def setUp(self):
        self.env = mock.patch.dict(os.environ, {"X_BEARER_TOKEN": "t", "ZDW_X_MAX_POSTS": "200"})
        self.env.start()
        self.users = mock.patch.object(xsource.feeds, "read_list", return_value=["111", "222"])
        self.users.start()

    def tearDown(self):
        self.env.stop()
        self.users.stop()

    def run_x(self, get, state=None):
        st = state if state is not None else {"users": {}}
        items = xsource.fetch_x(KEV, get=get, state=st, save=False)
        return items, st

    def test_skipped_without_token(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(xsource.fetch_x(KEV, save=False), [])

    def test_ids_only_no_text_leaves_the_module(self):
        def get(path, params, token):
            return {"data": [{"id": "5", "text": "SECRET TEXT: CVE-2026-1234 actively exploited"},
                             {"id": "6", "text": "lunch was great"}], "meta": {"newest_id": "6"}}
        items, st = self.run_x(get)
        self.assertEqual([i["id"] for i in items], ["x:5"])
        self.assertNotIn("SECRET", repr(items))
        self.assertEqual(items[0]["url"], "https://x.com/i/status/5")
        self.assertEqual(items[0]["title"], "X post mentioning CVE-2026-1234")
        self.assertEqual(items[0]["label"], "kev_exploited")
        self.assertEqual(st["users"]["111"], "6")  # cursor advances even past unclassified posts
        self.assertEqual(st["search"], "6")

    def test_since_id_used_after_first_run(self):
        seen = []
        def get(path, params, token):
            seen.append(params)
            return {"data": [], "meta": {}}
        self.run_x(get, {"users": {"111": "42"}, "search": "7"})
        self.assertEqual(seen[0]["since_id"], "42")
        self.assertEqual(seen[0]["max_results"], 100)
        self.assertEqual(seen[1]["max_results"], 10)  # user 222 has no cursor yet
        self.assertEqual(seen[2]["since_id"], "7")

    def test_rate_limit_stops_without_raising(self):
        def get(path, params, token):
            raise xsource.XStop("HTTP 429")
        items, _ = self.run_x(get)
        self.assertEqual(items, [])

    def test_budget_caps_reads(self):
        os.environ["ZDW_X_MAX_POSTS"] = "3"
        calls = []
        def get(path, params, token):
            calls.append(path)
            return {"data": [{"id": str(n), "text": "x"} for n in range(5)], "meta": {"newest_id": "4"}}
        self.run_x(get)
        self.assertEqual(len(calls), 1)  # 5 posts read >= budget 3, remaining jobs skipped


if __name__ == "__main__":
    unittest.main()
