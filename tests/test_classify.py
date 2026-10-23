import unittest

from zdwatch.classify import classify

KEV = {"CVE-2026-1111": "2026-10-01"}


def item(title):
    return {"id": "x", "title": title}


class ClassifyTest(unittest.TestCase):
    def test_kev(self):
        self.assertEqual(classify(item("Patch CVE-2026-1111 now"), KEV)["label"], "kev_exploited")

    def test_zero_day_reported(self):
        r = classify(item("Chrome zero-day exploited in the wild"), KEV)
        self.assertEqual(r["label"], "zero_day_reported")

    def test_mention_only(self):
        self.assertEqual(classify(item("Selling a 0day?"), KEV)["label"], "zero_day_mention")

    def test_exploited_with_cve(self):
        r = classify(item("CVE-2026-2222 actively exploited"), KEV)
        self.assertEqual(r["label"], "exploited_reported")

    def test_irrelevant_dropped(self):
        self.assertIsNone(classify(item("Show HN: my new editor"), KEV))


if __name__ == "__main__":
    unittest.main()
