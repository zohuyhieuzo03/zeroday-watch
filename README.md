# zeroday-watch

Watches public forums for talk about exploited vulnerabilities and labels each item by the **evidence** it carries. It is a lead feed, not a source of truth: confirm anything important with the vendor or CISA.

Feed (updated hourly by GitHub Actions):

- Live page: https://zeroday.zohuyhieuzo.cloud/
- JSON: [`docs/feed.json`](docs/feed.json)
- RSS: [`docs/feed.xml`](docs/feed.xml) (only `kev_exploited`, `zero_day_reported`, `exploited_reported`)

## Sources

- Hacker News (Algolia search API)
- Lobsters (`/t/security.json`)
- Node.js security releases (official vulnerability feed) and GitLab patch releases (official Atom feed); labelled `vendor_advisory`, with `severity` (GitLab: "critical" from the title; Node.js: highest severity stated in the post)
- GitHub Security Advisories (reviewed; critical, plus high for the last 3 days) as `vendor_advisory`, and public repos named for a CVE (`github-poc`, labelled `public_exploit_reported`, stars as points). A repo existing is not evidence of exploitation.
- Researcher blogs and news sites over RSS/Atom, list in [`config/blog_feeds.txt`](config/blog_feeds.txt) (titles and links only)
- Bluesky accounts through the public AppView, list in [`config/bluesky_accounts.txt`](config/bluesky_accounts.txt) (short post text and link; reposts skipped)
- X, optional, official API only, off unless the `X_BEARER_TOKEN` secret is set. See "X" below.
- CISA KEV catalog, read from the [`cisagov/kev-data`](https://github.com/cisagov/kev-data) mirror

Only titles, links and counters are stored. No post bodies, no usernames, nothing from closed forums.

## X

X's developer terms allow a third party to redistribute Post IDs, not content. So the X source is ID-only: post text is read into memory, run through the same rules, and dropped. The feed keeps `x.com/i/status/<id>`, our own label, CVE ids found in the post and a neutral title ("X post mentioning CVE-…"). No text, handles or counts are stored, and the LLM judge never sees X text. A post alone cannot become `kev_exploited`; only a CVE that CISA KEV lists can.

Cost is pay-per-use ($0.005 per post read at the time of writing, see [docs.x.com](https://docs.x.com/x-api/getting-started/pricing)). `ZDW_X_MAX_POSTS` (default 200) caps posts read per run, and the cursor in `state/x_state.json` makes every run fetch only new posts. Put numeric user ids in [`config/x_user_ids.txt`](config/x_user_ids.txt). This project is independent of X. See `x-data-access-research.md` in the author's notes for the full reasoning; scraping X is deliberately not supported.

## Labels

| Label | Meaning |
|---|---|
| `kev_exploited` | A CVE in the title is in CISA KEV. Exploited in the wild, but KEV does not say whether it was a 0-day. |
| `zero_day_reported` | Title says zero-day and mentions exploitation or no patch. A claim, unconfirmed. |
| `exploited_reported` | Title mentions exploitation and a CVE, no zero-day wording. |
| `vendor_advisory` | First-party advisory from Node.js or GitLab. A fix is already out, so this is patched vulnerability news, not an exploitation claim. Becomes `kev_exploited` if any of its CVEs is in KEV. |
| `unpatched_reported` | Title says unpatched / no patch / no fix with no exploitation claim. Disclosed, not known to be under attack. |
| `public_exploit_reported` | CVE plus "exploit"/PoC wording in the title. Exploit code exists; in-the-wild use is not claimed. |
| `zero_day_mention` | Zero-day wording only. Treat as rumor. |
| `related` | Has a CVE id, no exploitation signal. |

Labels can change as KEV updates; each item keeps a `label_history`.

## LLM judge (optional)

If `OPENROUTER_API_KEY` is set, each item also gets an `llm` field from OpenRouter's [Decisions API](https://openrouter.ai/docs/guides/community/jev-tutorial.md) (alpha): a `choice` question (`zero_day`, `n_day_exploited`, `disclosed_unpatched`, `not_exploited`, `unclear`) plus a yes/no "exploited" question, asked of two free decision models (`respan/span-01-lite` was tried and rejected: it only accepts chat-span input, HTTP 400 on this payload). `llm.consensus` is the label that confident models agree on. `unclear` answers and answers under 0.6 confidence abstain; it is `disputed` only when two confident labels differ, and `unclear` when everyone abstains. `llm.votes` says how many models actually voted, so a label with `votes: 1` is weaker than one with `votes: 2`.

The judge never rewrites `label`. Only `kev_exploited` is backed by a primary source; an LLM verdict of `zero_day` is still a claim.

Env: `ZDW_MODELS` (comma list, default `inception/mercury-decide:free,baseten/mammoth-1:free`), `ZDW_MAX_LLM_ITEMS` (default 10 per run, because free tiers are rate limited). In Actions, add the key as the `OPENROUTER_API_KEY` repo secret. It stops for the run on HTTP 401/402/403/429.

## Run locally

Python 3.9+, standard library only.

```bash
python3 -m unittest discover -s tests -t .
python3 -m zdwatch.run
```

## Limits and roadmap

- Rules read titles only, so they miss anything the title does not say.
- The LLM judge has had a live smoke test (3 headlines, 3 free models, all plausible) but no real eval; its quality on security headlines is not measured yet.
- Next: primary-source confirmation (vendor advisories, Project Zero "In the Wild") before anything is called a confirmed 0-day.
- Next: lead-time metric, i.e. how many hours before KEV a forum signal appeared.

## License

MIT
