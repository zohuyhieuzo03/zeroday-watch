import unittest

from zdwatch import topics

NOW = 1_800_000_000


def it(i, title, pts=1, label="security_news", src="hackernews", cves=()):
    return {"id": i, "title": title, "points": pts, "label": label, "source": src, "cves": list(cves),
            "kev": [], "first_seen": "2027-01-15T07:00:00Z"}


class TopicsTest(unittest.TestCase):
    def test_rarest_token_wins(self):
        items = [
            it("1", "Node2Shell: Brotli bug lets attackers run code"),
            it("2", "Node2Shell exploit for Node.js released"),
            it("3", "How Node2Shell works"),
            it("4", "Node.js ships a fix", label="related"),
            it("5", "Node.js adds a feature", label="related"),
            it("6", "Node.js again", label="related"),
        ]
        names = [t["name"].lower() for t in topics.compute(items, NOW)]
        self.assertIn("node2shell", names)
        self.assertIn("node.js", names)
        n2s = next(t for t in topics.compute(items, NOW) if t["name"].lower() == "node2shell")
        self.assertEqual(n2s["threads"], 3)

    def test_needs_three_threads_and_ignores_kev_source(self):
        items = [it("1", "Foobarbaz thing"), it("2", "Foobarbaz again"),
                 it("3", "Foobarbaz kev", src="cisa-kev")]
        self.assertEqual(topics.compute(items, NOW), [])

    def test_groups_sharing_a_cve_merge(self):
        items = [
            it("1", "Php2shell is bad", cves=["CVE-2026-1"]),
            it("2", "Php2shell again", cves=["CVE-2026-1"]),
            it("3", "Php2shell scanner", cves=["CVE-2026-1"]),
            it("4", "Patch for CVE-2026-1", cves=["CVE-2026-1"], label="related"),
            it("5", "Notes on CVE-2026-1", cves=["CVE-2026-1"], label="related"),
            it("6", "More on CVE-2026-1", cves=["CVE-2026-1"], label="related"),
        ]
        ts = topics.compute(items, NOW)
        self.assertEqual(len(ts), 1)
        self.assertEqual(ts[0]["threads"], 6)
        self.assertEqual(ts[0]["name"].lower(), "php2shell")

    def test_poc_repos_count_separately_and_stars_are_not_points(self):
        items = [
            it("1", "Php2shell bad", pts=10, cves=["CVE-2026-7"]),
            it("2", "Php2shell worse", pts=5, cves=["CVE-2026-7"]),
            it("3", "Php2shell worst", pts=1, cves=["CVE-2026-7"]),
            it("4", "owner/php2shell-poc: CVE-2026-7", pts=1700, label="public_exploit_reported",
               src="github-poc", cves=["CVE-2026-7"]),
        ]
        t = topics.compute(items, NOW)[0]
        self.assertEqual((t["threads"], t["repos"], t["points"]), (3, 1, 16))

    def test_plain_word_without_signal_is_not_a_topic(self):
        items = [it(str(n), "Zebrafish discussion thread") for n in range(4)]
        self.assertEqual(topics.compute(items, NOW), [])

    def test_generic_words_do_not_form_topics(self):
        items = [it(str(n), "Critical vulnerability patch released") for n in range(5)]
        self.assertEqual(topics.compute(items, NOW), [])


if __name__ == "__main__":
    unittest.main()
