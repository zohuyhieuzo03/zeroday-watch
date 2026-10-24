import unittest
from unittest import mock

from zdwatch import sources


class GithubTest(unittest.TestCase):
    def test_advisory_mapping_and_pagination_stop(self):
        adv = {"ghsa_id": "GHSA-1", "cve_id": "CVE-2026-9", "summary": "Bad bug", "html_url": "https://x/1",
               "published_at": "2026-10-23T00:00:00Z",
               "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "pillow"}}]}
        with mock.patch.object(sources, "_gh_json", return_value=[adv]) as m:
            items = sources.fetch_github_advisories(7, pages=5)
        self.assertEqual(m.call_count, 2)  # critical + high, one short page each
        self.assertEqual(items[0]["title"], "Bad bug (pip/pillow)")
        self.assertEqual(items[0]["cves"], ["CVE-2026-9"])
        self.assertEqual(items[0]["severity"], "critical")

    def test_poc_needs_a_cve_in_name_or_description(self):
        repos = {"items": [
            {"full_name": "a/php2shell-poc", "description": "CVE-2026-1234 PoC", "html_url": "https://x/a",
             "stargazers_count": 50, "created_at": "2026-10-20T00:00:00Z"},
            {"full_name": "b/unrelated", "description": "nothing", "html_url": "https://x/b",
             "stargazers_count": 999, "created_at": "2026-10-20T00:00:00Z"},
        ]}
        with mock.patch.object(sources, "_gh_json", return_value=repos):
            items = sources.fetch_github_poc(7)
        self.assertEqual([i["id"] for i in items], ["ghpoc:a/php2shell-poc"])
        self.assertEqual(items[0]["points"], 50)
        self.assertEqual(items[0]["label"], "public_exploit_reported")


if __name__ == "__main__":
    unittest.main()
