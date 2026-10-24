import unittest

from zdwatch import run

KEV = {}


def stored(i, title, label, src="hackernews"):
    return {"id": i, "source": src, "title": title, "label": label, "cves": [], "kev": [],
            "label_history": [{"at": "t0", "label": label}]}


class ReclassifyTest(unittest.TestCase):
    def test_stale_label_is_corrected_and_noise_dropped(self):
        ex = {
            "a": stored("a", "Ethics of Agent Exploitation", "exploited_reported"),
            "b": stored("b", "Mass exploitation of Citrix NetScaler", "security_news"),
            "k": stored("k", "CVE-2026-1: Vendor Product - Name", "kev_exploited", src="cisa-kev"),
        }
        run.reclassify(ex, KEV, "t1")
        self.assertNotIn("a", ex)
        self.assertEqual(ex["b"]["label"], "exploited_reported")
        self.assertEqual(ex["b"]["label_history"][-1], {"at": "t1", "label": "exploited_reported"})
        self.assertIn("k", ex)  # first-party items are left alone


if __name__ == "__main__":
    unittest.main()
