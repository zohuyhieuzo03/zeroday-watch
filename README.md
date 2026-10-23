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

## Run locally

Python 3.9+, standard library only.

```bash
python3 -m unittest discover -s tests -t .
python3 -m zdwatch.run
```

## Limits and roadmap

- Rules read titles only, so they miss anything the title does not say.
- Next: an LLM judge for ambiguous items (OpenRouter free/decision models), with primary-source confirmation (vendor advisories, Project Zero "In the Wild") before anything is called a confirmed 0-day.
- Next: lead-time metric, i.e. how many hours before KEV a forum signal appeared.

## License

MIT
