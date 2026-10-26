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

    def test_exploitation_before_disclosure_without_cve(self):
        r = classify(item("Amazon identifies Oct 17 PHP2Shell exploitation prior to public disclosure"), KEV)
        self.assertEqual(r["label"], "exploited_reported")

    def test_exploitation_needs_attack_context(self):
        for title in ("Ethics of Agent Exploitation", "Exploration-Exploitation Dilemma",
                      "Windows Exploitation Techniques: Dangling COM Object Registrations"):
            self.assertNotEqual((classify(item(title), KEV) or {}).get("label"), "exploited_reported", title)
        for title in ("Amazon says PHP2Shell exploitation began 4 days before patches",
                      "Mass exploitation of Citrix NetScaler: What we currently know"):
            self.assertEqual(classify(item(title), KEV)["label"], "exploited_reported", title)

    def test_unpatched_without_security_context_is_dropped(self):
        self.assertIsNone(classify(item("My unpatched Windows XP box still runs"), KEV))

    def test_are_exploiting_counts_as_exploited(self):
        r = classify(item("Threat actors are exploiting a critical vulnerability in FooVPN"), KEV)
        self.assertEqual(r["label"], "exploited_reported")

    def test_unpatched_flaws_is_not_called_exploited(self):
        r = classify(item("Unpatched Tailscale SSH Flaws Could Let a Hacked Device Reach Root on Other Servers"), KEV)
        self.assertEqual(r["label"], "unpatched_reported")

    def test_flaw_wording_is_security_news(self):
        r = classify(item("Critical Flaw in Python's Popular Pillow Image Library Allows Code Execution"), KEV)
        self.assertEqual(r["label"], "security_news")

    def test_unpatched_zero_day_stays_zero_day(self):
        r = classify(item("Unpatched zero-day in FooVPN"), KEV)
        self.assertEqual(r["label"], "zero_day_reported")

    def test_public_exploit(self):
        r = classify(item("PHP2Shell (CVE-2026-109618) Exploit"), KEV)
        self.assertEqual(r["label"], "public_exploit_reported")

    def test_is_exploited_is_an_exploitation_claim_not_a_public_exploit(self):
        r = classify(item("CVE-2026-2222 is exploited"), KEV)
        self.assertEqual(r["label"], "exploited_reported")

    def test_irrelevant_dropped(self):
        self.assertIsNone(classify(item("Show HN: my new editor"), KEV))


if __name__ == "__main__":
    unittest.main()
