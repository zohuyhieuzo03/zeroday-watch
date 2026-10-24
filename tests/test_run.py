import unittest

from zdwatch import run, sources


class RunTest(unittest.TestCase):
    def test_norm_time_variants_sort_together(self):
        a = run.norm_time("2026-10-23T22:14:03Z")
        b = run.norm_time("2026-10-23T09:12:45.000-05:00")
        self.assertEqual(a, "2026-10-23T22:14:03Z")
        self.assertEqual(b, "2026-10-23T14:12:45Z")
        self.assertIsNone(run.norm_time("nope"))

    def test_kev_items_window(self):
        entries = [
            {"cveID": "CVE-2026-1", "vendorProject": "V", "product": "P", "vulnerabilityName": "N", "dateAdded": "2099-01-01"},
            {"cveID": "CVE-2000-1", "dateAdded": "2000-01-01"},
        ]
        items = sources.kev_items(entries, 3)
        self.assertEqual([i["id"] for i in items], ["kev:CVE-2026-1"])
        self.assertEqual(items[0]["label"], "kev_exploited")
        self.assertEqual(items[0]["kev"], ["CVE-2026-1"])


if __name__ == "__main__":
    unittest.main()
