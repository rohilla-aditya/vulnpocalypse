# VULN-POCALYPSE NOW

A public, read-only terminal of what is on fire on the internet right now:
vulnerabilities being exploited in the wild, fresh critical CVEs, and companies
that just got hacked. Rescraped from public sources every hour.

| Tab | Sources |
|---|---|
| `[1]` Exploited in the wild | CISA Known Exploited Vulnerabilities, ransomware use flagged |
| `[2]` Critical + high CVEs | NVD (critical: 7 days, high: 3 days), GitHub Advisory Database |
| `[3]` Advisories | 19 vendor and CERT feeds: Microsoft, Cisco, Palo Alto, Fortinet, Chrome, Ubuntu, Debian, Arch, Jenkins, GitLab, Node.js, Drupal, RustSec, CERT/CC, NCSC UK, CERT-FR, JPCERT, Canada, Australia |
| `[4]` Public exploits | Exploit-DB, Zero Day Initiative (published + upcoming), Full Disclosure, oss-security, CXSecurity, Sploitus |
| `[5]` Pwned ledger | Have I Been Pwned breach catalogue; SEC 8-K Item 1.05 incident disclosures when `SEC_USER_AGENT` is set |
| `[6]` Ransom claims | ransomware.live: victims named on leak sites (attackers' claims, labelled unconfirmed, leak sites never linked) |
| `[7]` Breach wire | 42 security outlets and vendor research blogs, filtered to breach and vulnerability headlines |
| `[8]` Chatter | Hacker News, Lobsters, Reddit (netsec, cybersecurity, blueteamsec), infosec.exchange trending links |
| `[9]` Attacks in the news | Detected automatically: a company or crew that two or more independent sources are reporting an attack on in the last 7 days, with a link to each story |

### Attacks in the news

Nothing to configure. Each scrape, `app/incidents.py` pulls candidate names out
of every breach headline (press, Hacker News, forums, fediverse), keeps the
ones that several independent sources agree on, prefers the longest form of a
name, and drops vendors that appear in patch news as often as breach news. It
is a heuristic over headlines, not a language model, so expect the occasional
odd row.

### Patch status

Every row in the two vulnerability tabs carries one of three labels:

| Label | Meaning | Decided from |
|---|---|---|
| `PATCH AVAILABLE` | A fix has been published. It does not mean everyone has applied it. | NVD "Patch" references and fixed-version ranges, GitHub's first patched version, the CVE record, or wording such as "fixed in" |
| `NO PATCH` | The source says there is no fix: unpatched, end-of-life, won't fix. | Explicit wording, or a GitHub advisory with no patched version |
| `PATCH UNKNOWN` | The data does not say either way. Common for CVEs published in the last few days. | Nothing above matched |

CVE rows are annotated with their EPSS score (FIRST.org's probability of
exploitation in the next 30 days). The full lists live at the top of
`app/sources.py`.

Keys: `1`-`9` switch feed, `/` grep (searches every feed), `p` toggles green/amber phosphor, `esc` clears.

## Run it

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
# http://127.0.0.1:8000
```

No configuration is required. Every source is open and keyless; see
`.env.example` for the optional knobs (`REFRESH_SECONDS`, `NVD_API_KEY`,
`GITHUB_TOKEN`, `PUBLIC_URL`, `SEC_USER_AGENT`).

## How it works

- `app/sources.py` — one coroutine per source, each returning rows in a single
  flat shape (`ts`, `ref`, `sev`, `title`, `url`, `summary`, `source`, `tags`).
  Adding a source is one function plus one line in `SOURCES`.
- `app/feed.py` — scrapes all sources concurrently on a timer. A source that
  fails keeps its last good rows and shows as `[FAILED]` in the footer, so one
  flaky upstream never blanks the page. The last scrape is cached on disk and
  reloaded on restart.
- `app/main.py` — `GET /api/feed` (the whole dashboard as JSON, cached 60 s),
  `GET /api/health`, and the static frontend.
- `app/build.py` — one scrape written out as a static site, for GitHub Pages.
- `static/` — plain HTML/CSS/JS, no build step, no external requests.

Visitors never trigger a scrape: the page only reads the cached copy, so
traffic from a viral tweet costs upstreams nothing.

### Scraped content is untrusted

Text is stripped of markup and length-capped server-side, rendered with
`textContent` client-side, links must be `http(s)`, XML is parsed with
`defusedxml`, and the page ships a strict CSP (`script-src 'self'`).

## Deploy

### GitHub Pages (free, no server)

`.github/workflows/pages.yml` runs `python -m app.build dist`
every hour and publishes the result: the same frontend with the scrape baked in
as `feed.json`. One-time setup: **repo Settings → Pages → Source: GitHub
Actions**, then run the workflow once from the Actions tab. The site lands at
`https://rohilla-aditya.github.io/vulnpocalypse/`.

- GitHub may start scheduled runs a few minutes late, and pauses schedules on
  repos with no activity for 60 days.
- The last good scrape is kept in the Actions cache, so a source that is down
  for an hour keeps its previous rows.

### As a server

`uvicorn app.main:app --host 0.0.0.0 --port $PORT` runs the same page with the
scraper on a timer inside the process, on any host that runs Python. Set
`PUBLIC_URL` so the Twitter/OG card tags point at the right address.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

Tests run every scraper against canned upstream responses; no network needed.
CI also has a `live-scrape` job that hits the real upstreams and prints which
sources and feeds answered.
