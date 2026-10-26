import unittest
from unittest import mock

from zdwatch import sources

FEED = """<rss><channel>
<item><title>TS-2026-013</title><link>https://tailscale.com/security-bulletins/#ts-2026-013</link>
<pubDate>Wed, 21 Oct 2026 00:00:00 GMT</pubDate>
<description>&lt;p&gt;&lt;strong&gt;&lt;em&gt;Description&lt;/em&gt;&lt;/strong&gt;: Leaked private keys for eMudhra TLS intermediate certificates&lt;/p&gt;&lt;h3&gt;What happened?&lt;/h3&gt;&lt;p&gt;Long text CVE-2026-1234&lt;/p&gt;</description></item>
<item><title>TS-2020-001</title><link>https://x</link><pubDate>Mon, 01 Jan 2024 00:00:00 GMT</pubDate><description>old</description></item>
</channel></rss>"""


class TailscaleTest(unittest.TestCase):
    def test_headline_comes_from_description_and_old_entries_are_cut(self):
        with mock.patch.object(sources, "_get_text", return_value=FEED), \
             mock.patch.object(sources.time, "time", return_value=1792999000):  # 2026-10-26
            items = sources.fetch_tailscale_advisories(30)
        self.assertEqual(len(items), 1)
        it = items[0]
        self.assertEqual(it["title"], "Tailscale TS-2026-013: Leaked private keys for eMudhra TLS intermediate certificates")
        self.assertEqual(it["id"], "tailscale:ts-2026-013")
        self.assertEqual(it["url"], "https://tailscale.com/security-bulletins/#ts-2026-013")
        self.assertEqual(it["cves"], ["CVE-2026-1234"])
        self.assertEqual(it["label"], "vendor_advisory")


if __name__ == "__main__":
    unittest.main()
