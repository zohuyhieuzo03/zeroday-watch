# zeroday-watch

Watches public forums for talk about exploited vulnerabilities and labels each item by the **evidence** it carries. It is a lead feed, not a source of truth: confirm anything important with the vendor or CISA.

Feed (updated hourly by GitHub Actions):

- JSON: [`docs/feed.json`](docs/feed.json)
- RSS: [`docs/feed.xml`](docs/feed.xml) (only `kev_exploited`, `zero_day_reported`, `exploited_reported`)

## Sources

- Hacker News (Algolia search API)
- Lobsters (`/t/security.json`)
- CISA KEV catalog, read from the [`cisagov/kev-data`](https://github.com/cisagov/kev-data) mirror

Only titles, links and counters are stored. No post bodies, no usernames, nothing from closed forums.

## Labels

| Label | Meaning |
|---|---|
| `kev_exploited` | A CVE in the title is in CISA KEV. Exploited in the wild, but KEV does not say whether it was a 0-day. |
| `zero_day_reported` | Title says zero-day and mentions exploitation or no patch. A claim, unconfirmed. |
| `exploited_reported` | Title mentions exploitation and a CVE, no zero-day wording. |
| `zero_day_mention` | Zero-day wording only. Treat as rumor. |
| `related` | Has a CVE id, no exploitation signal. |

Labels can change as KEV updates; each item keeps a `label_history`.

## LLM judge (optional)

If `OPENROUTER_API_KEY` is set, each item also gets an `llm` field from OpenRouter's [Decisions API](https://openrouter.ai/docs/guides/community/jev-tutorial.md) (alpha): a `choice` question (`zero_day`, `n_day_exploited`, `disclosed_unpatched`, `not_exploited`, `unclear`) plus a yes/no "exploited" question, asked of two free decision models. `llm.consensus` is a label only when every model agrees with confidence ≥ 0.6, otherwise `disputed` or `unclear`.

The judge never rewrites `label`. Only `kev_exploited` is backed by a primary source; an LLM verdict of `zero_day` is still a claim.

Env: `ZDW_MODELS` (comma list, default `respan/span-01-lite:free,inception/mercury-decide:free`), `ZDW_MAX_LLM_ITEMS` (default 10 per run, because free tiers are rate limited). In Actions, add the key as the `OPENROUTER_API_KEY` repo secret. It stops for the run on HTTP 401/402/403/429.

## Run locally

Python 3.9+, standard library only.

```bash
python3 -m unittest discover -s tests -t .
python3 -m zdwatch.run
```

## Limits and roadmap

- Rules read titles only, so they miss anything the title does not say.
- The LLM judge has only been tested against mocked responses; its quality on security headlines is not measured yet.
- Next: primary-source confirmation (vendor advisories, Project Zero "In the Wild") before anything is called a confirmed 0-day.
- Next: lead-time metric, i.e. how many hours before KEV a forum signal appeared.

## License

MIT
