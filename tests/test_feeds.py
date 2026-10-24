import unittest
from datetime import datetime, timezone

from zdwatch import feeds

RSS = """<rss version="2.0"><channel>
<item><title>  Exploiting  CVE-2026-1234 in the wild </title><link>https://b/1</link><pubDate>Fri, 23 Oct 2026 10:00:00 GMT</pubDate></item>
<item><title>Old post</title><link>https://b/0</link><pubDate>Mon, 01 Jan 2024 10:00:00 GMT</pubDate></item>
</channel></rss>"""
ATOM = """<feed xmlns="http://www.w3.org/2005/Atom">
<entry><title>Zero-day found</title><link rel="alternate" href="https://a/1"/><published>2026-10-23T09:00:00Z</published></entry>
</feed>"""
SINCE = datetime(2026, 10, 1, tzinfo=timezone.utc).timestamp()


class FeedsTest(unittest.TestCase):
    def test_rss_cutoff_and_whitespace(self):
        got = feeds.parse_feed(RSS, SINCE)
        self.assertEqual([(t, l) for t, l, _ in got], [("Exploiting CVE-2026-1234 in the wild", "https://b/1")])

    def test_repairs_bare_ampersand(self):
        bad = RSS.replace("Exploiting  CVE", "Fish & Chips: CVE")
        got = feeds.parse_feed(bad, SINCE)
        self.assertEqual(got[0][0], "Fish & Chips: CVE-2026-1234 in the wild")

    def test_atom_alternate_link(self):
        got = feeds.parse_feed(ATOM, SINCE)
        self.assertEqual([(t, l) for t, l, _ in got], [("Zero-day found", "https://a/1")])

    def test_bluesky_post_item_and_repost_skipped(self):
        post = {"post": {"uri": "at://did:plc:x/app.bsky.feed.post/3abc", "likeCount": 4, "replyCount": 1,
                         "record": {"text": "New  CVE-2026-1\nexploited", "createdAt": "2026-10-23T09:00:00.000Z"}}}
        it = feeds.post_item("a.bsky.social", post, SINCE)
        self.assertEqual(it["url"], "https://bsky.app/profile/a.bsky.social/post/3abc")
        self.assertEqual(it["title"], "New CVE-2026-1 exploited")
        self.assertEqual(it["points"], 4)
        post["reason"] = {"$type": "repost"}
        self.assertIsNone(feeds.post_item("a.bsky.social", post, SINCE))


if __name__ == "__main__":
    unittest.main()
