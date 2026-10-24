import unittest

from zdwatch import judge, sources


class VendorTest(unittest.TestCase):
    def test_advisory_shape(self):
        a = sources._advisory("gitlab", "k", "t", "https://x", "2026-10-21T00:00:00Z", ["cve-2026-1", "CVE-2026-1", "CVE-2026-2"], "critical")
        self.assertEqual(a["cves"], ["CVE-2026-1", "CVE-2026-2"])
        self.assertEqual(a["label"], "vendor_advisory")
        self.assertEqual(a["id"], "gitlab:k")

    def test_primary_sources_are_not_judged(self):
        for src in ("nodejs", "gitlab", "cisa-kev"):
            self.assertFalse(judge.needs_judging({"source": src, "title": "x"}))
        self.assertTrue(judge.needs_judging({"source": "hackernews", "title": "x"}))


if __name__ == "__main__":
    unittest.main()
