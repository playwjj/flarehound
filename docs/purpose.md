# Traffic by purpose

FlareHound breaks traffic down by user agent, network, IP and path. Those say *who*; what decides the response is *why the traffic comes*. Two user agents of the same size can call for opposite answers: a training crawler (blocking it costs nothing), a fetch a person triggered in an assistant (a real person asking — blocking it blocks demand), a fetch API serving its customers (B2B data use — rate-limit or point to an API, don't block IPs). The purpose facet puts that answer in the daily report, the console and the alerts.

It adds no data source, no token and no write path, and it never acts on its own.

## The six classes

| Class | What it is | Examples | Reports lean towards |
|---|---|---|---|
| `training` | collects corpus to train models | GPTBot, ClaudeBot, CCBot, Bytespider, Meta-ExternalAgent | blocking costs almost no referrals |
| `search` | indexes for search, AI search included | OAI-SearchBot, Claude-SearchBot, PerplexityBot, Applebot | brings citations and visits — careful |
| `user_action` | fetches live while a person asks an assistant | ChatGPT-User, Claude-User, Perplexity-User, Meta-ExternalFetcher | a person is behind it — treat as human |
| `tool` | a fetch API / platform fetching for its customers | Exa, Firecrawl, Diffbot, rednote-websearch-bot | B2B data use: rate-limit, charge, point to an API |
| `mixed` | search and training in one crawler | Googlebot, Bingbot, Amazonbot | not split by its operator — labelled mixed |
| `undeclared` | browser user agents with automation traits | headless-browser fleets on cloud machines | **traits only — never an AI operator** |

User agents outside these classes stay untagged: the facet covers AI-related crawlers and undeclared automation, not every bot (SEO crawlers such as AhrefsBot are not listed).

## Where the labels come from

- **Built-in table.** A snapshot of the community [ai.robots.txt](https://github.com/ai-robots-txt/ai.robots.txt) list (user agent → operator → purpose; Cloudflare Radar's AI statistics use the same list), shipped with each release. FlareHound never fetches it at run time. Matching is case-insensitive: an exact match first, then the longest contained marker.
- **Your overrides.** `purposes` in `config.json` or **Settings → Network names → Traffic purposes** in the console: a UA substring and its class (`none` removes it from every class). Overrides win over the table; console changes are audited like every setting.
- **Trust, shown with every label.**
  - *verified* — at least 90 % of the UA's requests pass Cloudflare's verified-bot check (`cf.client.bot`);
  - *self-declared* — the UA names itself but is not verified (anyone can write "GPTBot");
  - *by traits* — undeclared automation.
- **Undeclared automation** is a browser user agent (Chrome, Firefox, Safari, Edge) served from a **hosting / cloud network** (FlareHound's network table and the registered names the archive keeps), or a headless browser. It needs the ASN dimension: on Free it is not judged and the report says so. It is a conclusion about traits; nothing ever renders it as "probably some AI".
- **Applied when shown, never stored.** The archive keeps raw user agents; the table is applied when a report or page is rendered, so a revised table re-labels history consistently. The daily report names the table version.

## Daily report

A section after the top lists:

```
Traffic by purpose (table 2026-11-20; the UA groups read cover 97% of requests):
- undeclared automation 41.0%: 240,512 (yesterday 29.0%, +48.2%) — browser user agents with automation traits (hosting networks, headless); Top: Chrome/157.0.0.0 (X11; Linux x86_64) 214,057 (AS45102 aliyun 98%), …
- search indexing 18.0%: … ; Top: Applebot 12,400 [verified], …
- training 6.0%: … ; Top: GPTBot 8,000 [verified], ClaudeBot 3,100 [verified], …
- fetch tools 2.0%: … ; Top: rednote-websearch-bot 7,598 [self-declared], …
```

Each class: share of the window's requests, count, yesterday's share and the change, the top 3 user agents with their trust. When a class's share moves by **10 percentage points** or more since yesterday, the conclusion line names it ("Traffic by purpose moved: undeclared automation 29% → 41% (+12 pp)"). Two extra GraphQL queries per report (the window and the day before, UA × network × verified bot, 2,000 groups each).

## Alerts

A new user agent in the Top 10 carries its purpose: `New user agent in Top 10: "…", 9,000 requests [training · OpenAI · verified]`.

- A new **training** crawler that is verified (or that the plan cannot verify) is **recorded, not alerted on**: archived like every face, logged, and listed in the daily report ("new training crawler (recorded, not alerted)").
- A self-declared, unverified training UA alerts as before, labelled — it may be anyone.
- New `tool` and `undeclared` faces alert as before, labelled.

No threshold changes: only the wording and the training exception.

## Console

- A purpose badge next to user agents on the movers, new faces, live faces, blocked board and drill-down lists (hover: operator and trust). Lists carry no traffic evidence, so their badges come from the table alone; verification and undeclared automation are on the drill-down. IPs get no badge — purpose is a property of the user agent.
- **Filter by purpose** on the movers (user agents) and new faces pages.
- **Drill-down:** a user agent shows its label with trust (verified / self-declared / by traits); a network shows its traffic split by purpose — "what is AS45102 made of" answered in one table.

## Command line

```
flarehound purpose [--zone NAME] [--hours 24] [--asn 45102]
```

The section above for the last N whole hours against the same hours a day earlier, for the zone or for one network's slice (read token).

## doctor

`flarehound doctor` prints the table version, its entry count and the overrides in effect. If the table cannot be read, the facet turns itself off — reports, console and alerts behave exactly as without it — and `doctor` says why.
