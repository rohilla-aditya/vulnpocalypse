"""Scrapers. One coroutine per public source, each returning normalized items.

Every item is a flat dict the frontend can render without knowing where it
came from:

    id       stable unique key
    ts       unix seconds (when it was published / added)
    ref      short left-hand label: a CVE id, "▲ 312", "4.2M accts"
    sev      critical | high | medium | low | "" (drives the colour)
    title    one line
    url      http(s) link to the original
    summary  one or two plain-text sentences
    source   who said so
    tags     small list of uppercase flags (RANSOMWARE, BREACH, ...)

Everything scraped is untrusted: text is stripped of markup and length-capped,
URLs must be http(s), and XML goes through defusedxml.
"""

from __future__ import annotations

import asyncio
import html
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Awaitable, Callable

import httpx
from defusedxml import ElementTree as ET

from .config import settings

USER_AGENT = "vuln-pocalypse/1.0 (public security dashboard; hourly refresh)"
TIMEOUT = httpx.Timeout(30.0, connect=10.0)
MAX_BODY = 8_000_000  # bytes; anything larger is not a feed we want to parse
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")

BREACH_RE = re.compile(
    r"\b(breach\w*|hacked|hackers?|hack|ransomware|data (?:leak|theft)|leak(?:ed|s)?|stolen|stole|steals?"
    r"|extort\w*|cyber ?attacks?|compromised?|intrusion|exposed|exposes|outage after|attack(?:ed|ers)?)\b",
    re.I,
)
VULN_RE = re.compile(
    r"\b(CVE-\d{4}-\d{3,}|zero[- ]days?|0-?days?|vulnerabilit\w+|exploit\w*|RCE|remote code execution"
    r"|patch\w*|flaws?|bugs?|backdoor\w*|malware|supply[- ]chain|botnet|phishing)\b",
    re.I,
)


# --------------------------------------------------------------------------
# Sanitizing helpers
# --------------------------------------------------------------------------

def clean(text: object, limit: int = 300) -> str:
    """Plain text from scraped markup: no tags, no entities, bounded length."""
    if not isinstance(text, str):
        return ""
    text = html.unescape(_TAG_RE.sub(" ", html.unescape(text)))
    text = re.sub(r" ([.,;:!?])", r"\1", _WS_RE.sub(" ", text).strip())
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


def safe_url(url: object) -> str:
    if isinstance(url, str):
        url = url.strip()
        if url.startswith(("https://", "http://")) and len(url) < 2000 and not _WS_RE.search(url):
            return url
    return ""


def iso_ts(value: object) -> int:
    """ISO-8601 (date or datetime, with or without zone) -> unix seconds, 0 if unparseable."""
    if not isinstance(value, str) or not value:
        return 0
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return 0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def rfc822_ts(value: object) -> int:
    if not isinstance(value, str) or not value:
        return 0
    try:
        dt = parsedate_to_datetime(value.strip())
    except (TypeError, ValueError):
        return iso_ts(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def classify(text: str) -> str:
    """BREACH if someone got hit, VULN if something is broken, else ''."""
    if BREACH_RE.search(text):
        return "BREACH"
    if VULN_RE.search(text):
        return "VULN"
    return ""


def human_count(n: int) -> str:
    for size, suffix in ((1_000_000_000, "B"), (1_000_000, "M"), (1_000, "K")):
        if n >= size:
            return f"{n / size:.1f}".rstrip("0").rstrip(".") + suffix
    return str(n)


def _sev_from_score(score: object) -> str:
    try:
        s = float(score)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return ""
    return "critical" if s >= 9 else "high" if s >= 7 else "medium" if s >= 4 else "low"


# Patch status of a vulnerability: is a fix published, or is it still open?
#   patched  a fixed version, patch or update exists (not: everyone applied it)
#   open     the source says there is no fix (unpatched, end-of-life, won't fix)
#   unknown  the data does not say either way
FIX_LABEL = {"patched": "PATCH AVAILABLE", "open": "NO PATCH", "unknown": "PATCH UNKNOWN"}

_NOFIX_RE = re.compile(
    r"\b(no (?:known |official |available )?(?:patch|fix|update)(?:es)?\b|unpatched|remains? unfixed|not (?:yet )?(?:been )?(?:fixed|patched)"
    r"|end[- ]of[- ]life|\bEoL\b|no longer (?:supported|maintained)|unsupported when assigned|will not (?:be )?(?:fix|patch)\w*"
    r"|won't (?:be )?(?:fix|patch)\w*|should be disconnected)",
    re.I,
)
_FIXED_RE = re.compile(
    r"\b(fixed in|patched in|addressed in|resolved in|remediated in|(?:is|was|has been|have been|been) (?:fixed|patched|addressed|resolved|remediated)"
    r"|fix(?:es)? (?:is |are )?available|patch(?:es)? (?:is |are )?available|upgrade to|update to|updating to|upgrading to"
    r"|apply (?:the )?(?:updates?|patch(?:es)?)|(?:prior to|before|earlier than|through|up to) (?:version )?v?\d|contains? a (?:fix|patch)|a fix (?:has been|was) released)",
    re.I,
)


def fix_from_text(*texts: object) -> str:
    """Best guess from prose. "No fix" wording wins over "fixed" wording."""
    text = " ".join(t for t in texts if isinstance(t, str))
    if _NOFIX_RE.search(text):
        return "open"
    if _FIXED_RE.search(text):
        return "patched"
    return "unknown"


def set_fix(item: dict, status: str) -> dict:
    """Record the patch status on a row and keep exactly one label for it."""
    labels = set(FIX_LABEL.values())
    item["fix"] = status
    item["tags"] = [t for t in item.get("tags", []) if t not in labels] + [FIX_LABEL[status]]
    return item


def fix_from_cve_record(record: dict) -> str:
    """Patch status from a CVE Program record (CVE JSON 5.x)."""
    containers = record.get("containers") or {}
    blocks = [containers.get("cna") or {}] + [a for a in containers.get("adp") or [] if isinstance(a, dict)]
    texts = []
    for block in blocks:
        for product in block.get("affected") or []:
            for version in (product or {}).get("versions") or []:
                # "affected below X" or an explicitly unaffected release means a fixed version exists.
                if isinstance(version, dict) and (version.get("lessThan") or version.get("status") == "unaffected"):
                    return "patched"
        for ref in block.get("references") or []:
            if any(str(t).lower() in ("patch", "release-notes") for t in (ref or {}).get("tags") or []):
                return "patched"
        texts += [d.get("value", "") for d in (block.get("descriptions") or []) + (block.get("solutions") or []) if isinstance(d, dict)]
        if block.get("solutions"):
            texts.append("fix is available")
    return fix_from_text(*texts)


CVE_RECORD_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}xxx/{cve}.json"


async def fetch_fix_status(client: httpx.AsyncClient, cves: list[str]) -> dict[str, str]:
    """Look up CVE records (static files on GitHub) and read their patch status."""
    gate = asyncio.Semaphore(8)

    async def one(cve: str) -> tuple[str, str | None]:
        _, year, number = cve.split("-")
        url = CVE_RECORD_URL.format(year=year, bucket=int(number) // 1000, cve=cve)
        try:
            async with gate:
                resp = await _get(client, url, timeout=15.0)
            return cve, fix_from_cve_record(resp.json())
        except Exception:
            return cve, None  # try again next scrape

    results = await asyncio.gather(*(one(c) for c in cves))
    return {cve: status for cve, status in results if status}


async def _get(client: httpx.AsyncClient, url: str, **kwargs) -> httpx.Response:
    resp = await client.get(url, **kwargs)
    resp.raise_for_status()
    if len(resp.content) > MAX_BODY:
        raise ValueError("response too large")
    return resp


def _why(exc: BaseException) -> str:
    """Short public reason for a failed fetch: a status code or an exception class."""
    if isinstance(exc, httpx.HTTPStatusError):
        return f"HTTP {exc.response.status_code}"
    return type(exc).__name__


# --------------------------------------------------------------------------
# CISA Known Exploited Vulnerabilities — the "being used against people right
# now" list.
# --------------------------------------------------------------------------

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def fetch_kev(client: httpx.AsyncClient) -> dict:
    data = (await _get(client, KEV_URL)).json()
    rows = [v for v in data.get("vulnerabilities", []) if isinstance(v, dict)]
    now = time.time()
    items = []
    for v in rows:
        cve = clean(v.get("cveID"), 30)
        if not cve:
            continue
        ransomware = str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"
        vendor = clean(v.get("vendorProject"), 60)
        product = clean(v.get("product"), 80)
        due = clean(v.get("dueDate"), 12)
        items.append(
            {
                "id": f"kev:{cve}",
                "ts": iso_ts(v.get("dateAdded")),
                "ref": cve,
                "sev": "critical" if ransomware else "high",
                "title": clean(v.get("vulnerabilityName"), 160) or f"{vendor} {product}".strip(),
                "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                "summary": clean(v.get("shortDescription"), 320),
                "source": f"{vendor} · {product}".strip(" ·"),
                "tags": ["EXPLOITED"] + (["RANSOMWARE"] if ransomware else []) + ([f"DEADLINE {due}"] if due else []),
            }
        )
        # CISA's own wording settles some entries ("Apply updates...", "end-of-life");
        # the rest are resolved from the CVE record after the scrape.
        action = clean(v.get("requiredAction"), 400)
        set_fix(items[-1], "open" if _NOFIX_RE.search(action) else fix_from_text(action, v.get("shortDescription")))
    items.sort(key=lambda i: i["ts"], reverse=True)
    return {
        "items": items[:120],
        "stats": {
            "kev_total": len(items),
            "kev_ransomware": sum(1 for i in items if "RANSOMWARE" in i["tags"]),
            "kev_30d": sum(1 for i in items if now - i["ts"] < 30 * 86400),
        },
    }


# --------------------------------------------------------------------------
# NVD — every CRITICAL CVE published in the last week.
# --------------------------------------------------------------------------

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _nvd_score(metrics: dict) -> float | None:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in metrics.get(key) or []:
            score = (m.get("cvssData") or {}).get("baseScore")
            if isinstance(score, (int, float)):
                return float(score)
    return None


def _nvd_fix(cve: dict, desc: str) -> str:
    worded = fix_from_text(desc)
    if worded == "open":
        return "open"
    for ref in cve.get("references") or []:
        if "Patch" in ((ref or {}).get("tags") or []):
            return "patched"
    for config in cve.get("configurations") or []:
        for node in (config or {}).get("nodes") or []:
            for match in (node or {}).get("cpeMatch") or []:
                if (match or {}).get("versionEndExcluding"):
                    return "patched"
    return worded


async def _nvd_page(client: httpx.AsyncClient, severity: str, days: int) -> tuple[list[dict], int]:
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    fmt = "%Y-%m-%dT%H:%M:%S.000Z"
    headers = {"apiKey": settings.nvd_api_key} if settings.nvd_api_key else {}
    resp = await client.get(
        NVD_URL,
        params={
            "cvssV3Severity": severity,
            "pubStartDate": start.strftime(fmt),
            "pubEndDate": end.strftime(fmt),
            "resultsPerPage": 2000,
        },
        headers=headers,
        timeout=90.0,
    )
    resp.raise_for_status()
    data = resp.json()
    items = []
    for wrapper in data.get("vulnerabilities", []):
        cve = (wrapper or {}).get("cve") or {}
        cve_id = clean(cve.get("id"), 30)
        if not cve_id or cve.get("vulnStatus") == "Rejected":
            continue
        desc = next((d.get("value") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), "")
        score = _nvd_score(cve.get("metrics") or {})
        desc = clean(desc, 320)
        items.append(
            {
                "id": f"nvd:{cve_id}",
                "ts": iso_ts(cve.get("published")),
                "ref": cve_id,
                "sev": severity.lower(),
                "title": clean(desc, 140),
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "summary": desc if len(desc) > 140 else "",
                "source": "NVD",
                "tags": [f"CVSS {score:.1f}"] if score is not None else [],
            }
        )
        set_fix(items[-1], _nvd_fix(cve, desc))
    items.sort(key=lambda i: i["ts"], reverse=True)
    return items, int(data.get("totalResults") or len(items))


async def fetch_nvd(client: httpx.AsyncClient) -> dict:
    # Sequential on purpose: anonymous NVD access allows 5 requests per 30 s.
    critical, n_critical = await _nvd_page(client, "CRITICAL", 7)
    stats = {"nvd_critical_7d": n_critical}
    failed = []
    try:
        high, n_high = await _nvd_page(client, "HIGH", 3)
        stats["nvd_high_3d"] = n_high
    except Exception as exc:  # critical alone is still worth publishing
        high = []
        failed.append(f"HIGH severity ({_why(exc)})")
    return {"items": critical[:400] + high[:300], "stats": stats, "failed": failed}


# --------------------------------------------------------------------------
# GitHub Advisory Database — critical advisories in open-source packages.
# --------------------------------------------------------------------------

GHSA_URL = "https://api.github.com/advisories"


async def fetch_ghsa(client: httpx.AsyncClient) -> dict:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if settings.github_token:
        headers["Authorization"] = f"Bearer {settings.github_token}"

    async def page(severity: str) -> list:
        resp = await _get(
            client,
            GHSA_URL,
            params={"type": "reviewed", "severity": severity, "sort": "published", "direction": "desc", "per_page": 100},
            headers=headers,
        )
        data = resp.json()
        return data if isinstance(data, list) else []

    pages = await asyncio.gather(page("critical"), page("high"), return_exceptions=True)
    if all(isinstance(r, BaseException) for r in pages):
        raise pages[0]
    rows = [a for r in pages if not isinstance(r, BaseException) for a in r]
    items = []
    for a in rows if isinstance(rows, list) else []:
        ghsa = clean(a.get("ghsa_id"), 30)
        if not ghsa or a.get("withdrawn_at"):
            continue
        pkgs = []
        for v in a.get("vulnerabilities") or []:
            pkg = (v or {}).get("package") or {}
            name = clean(pkg.get("name"), 60)
            if name:
                label = f"{clean(pkg.get('ecosystem'), 20)}:{name}".lstrip(":")
                if label not in pkgs:
                    pkgs.append(label)
        fixes = [bool((v or {}).get("first_patched_version")) for v in a.get("vulnerabilities") or []]
        fix = "patched" if fixes and any(fixes) else "open" if fixes else "unknown"
        score = (a.get("cvss") or {}).get("score")
        items.append(
            {
                "id": f"ghsa:{ghsa}",
                "ts": iso_ts(a.get("published_at")),
                "ref": clean(a.get("cve_id"), 30) or ghsa,
                "sev": clean(a.get("severity"), 10).lower() or "high",
                "title": clean(a.get("summary"), 160),
                "url": safe_url(a.get("html_url")) or f"https://github.com/advisories/{ghsa}",
                "summary": ", ".join(pkgs[:4]),
                "source": "GitHub Advisories",
                "tags": ([f"CVSS {float(score):.1f}"] if isinstance(score, (int, float)) and score else []) + ["OSS"],
            }
        )
        set_fix(items[-1], fix)
    return {"items": items, "stats": {}}


# --------------------------------------------------------------------------
# Have I Been Pwned — the ledger of who lost what.
# --------------------------------------------------------------------------

HIBP_URL = "https://haveibeenpwned.com/api/v3/breaches"


async def fetch_hibp(client: httpx.AsyncClient) -> dict:
    rows = (await _get(client, HIBP_URL)).json()
    now = time.time()
    items = []
    for b in rows if isinstance(rows, list) else []:
        # Skip entries that are not "a company got hacked": fabricated dumps,
        # spam lists, retired records.
        if b.get("IsFabricated") or b.get("IsSpamList") or b.get("IsRetired"):
            continue
        name = clean(b.get("Name"), 80)
        title = clean(b.get("Title"), 100) or name
        if not name:
            continue
        pwned = b.get("PwnCount") if isinstance(b.get("PwnCount"), int) else 0
        classes = [clean(c, 40) for c in (b.get("DataClasses") or [])[:6]]
        breach_date = clean(b.get("BreachDate"), 12)
        summary = f"Breached {breach_date}. " if breach_date else ""
        if classes:
            summary += "Lost: " + ", ".join(c for c in classes if c) + ". "
        summary += clean(b.get("Description"), 220)
        tags = ["BREACH"]
        if not b.get("IsVerified", True):
            tags.append("UNVERIFIED")
        if b.get("IsSensitive"):
            tags.append("SENSITIVE")
        if b.get("IsMalware"):
            tags.append("MALWARE")
        items.append(
            {
                "id": f"hibp:{name}",
                "ts": iso_ts(b.get("AddedDate")),
                "ref": f"{human_count(pwned)} accts",
                "sev": "critical" if pwned >= 10_000_000 else "high" if pwned >= 1_000_000 else "medium",
                "title": title,
                "url": f"https://haveibeenpwned.com/Breach/{name}" if re.fullmatch(r"[\w.-]+", name) else "https://haveibeenpwned.com/PwnedWebsites",
                "summary": summary.strip(),
                "source": clean(b.get("Domain"), 80) or "Have I Been Pwned",
                "tags": tags,
                "n": pwned,
            }
        )
    items.sort(key=lambda i: i["ts"], reverse=True)
    recent = [i for i in items if now - i["ts"] < 365 * 86400]
    return {
        "items": items[:80],
        "stats": {
            "breaches_total": len(items),
            "breaches_365d": len(recent),
            "accounts_365d": sum(i["n"] for i in recent),
        },
    }


# --------------------------------------------------------------------------
# Hacker News — what the nerds are arguing about.
# --------------------------------------------------------------------------

HN_URL = "https://hn.algolia.com/api/v1/search_by_date"
HN_QUERIES = (
    "data breach", "breach", "hacked", "hackers", "ransomware", "leak", "CVE", "zero-day", "0day", "vulnerability",
    "exploit", "RCE", "backdoor", "malware", "supply chain attack", "phishing", "security incident", "security advisory",
)


async def fetch_hn(client: httpx.AsyncClient) -> dict:
    since = int(time.time()) - 7 * 86400

    async def one(query: str) -> list[dict]:
        resp = await _get(
            client,
            HN_URL,
            params={
                "query": query,
                "tags": "story",
                "hitsPerPage": 50,
                "numericFilters": f"created_at_i>{since},points>4",
            },
        )
        return resp.json().get("hits") or []

    results = await asyncio.gather(*(one(q) for q in HN_QUERIES), return_exceptions=True)
    if all(isinstance(r, BaseException) for r in results):
        raise next(r for r in results if isinstance(r, BaseException))

    seen: dict[str, dict] = {}
    for hits in results:
        if isinstance(hits, BaseException):
            continue
        for h in hits:
            oid = clean(str(h.get("objectID") or ""), 20)
            title = clean(h.get("title"), 200)
            if not oid.isdigit() or not title or oid in seen:
                continue
            # Algolia also matches on the linked page; keep only stories whose
            # own headline is on topic.
            tag = classify(title)
            if not tag:
                continue
            points = h.get("points") if isinstance(h.get("points"), int) else 0
            comments = h.get("num_comments") if isinstance(h.get("num_comments"), int) else 0
            link = safe_url(h.get("url"))
            domain = httpx.URL(link).host if link else "news.ycombinator.com"
            seen[oid] = {
                "id": f"hn:{oid}",
                "ts": int(h.get("created_at_i") or 0),
                "ref": f"▲ {points}",
                "sev": "critical" if points >= 500 else "high" if points >= 150 else "medium" if points >= 40 else "low",
                "title": title,
                "url": f"https://news.ycombinator.com/item?id={oid}",
                "summary": f"{comments} comments · {domain}",
                "source": "Hacker News",
                "tags": [tag],
                "link": link,
                "n": points,
            }
    items = sorted(seen.values(), key=lambda i: i["ts"], reverse=True)
    return {"items": items[:200], "stats": {}}


# --------------------------------------------------------------------------
# RSS / Atom / RDF feeds, in three groups: press, vendor advisories, exploits.
# --------------------------------------------------------------------------

NEWS_FEEDS: tuple[tuple[str, str], ...] = (
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    ("The Record", "https://therecord.media/feed"),
    ("SecurityWeek", "https://www.securityweek.com/feed/"),
    ("DataBreaches.net", "https://databreaches.net/feed/"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml"),
    ("The Register", "https://www.theregister.com/security/headlines.atom"),
    ("Security Affairs", "https://securityaffairs.com/feed"),
    ("CyberScoop", "https://cyberscoop.com/feed/"),
    ("TechCrunch", "https://techcrunch.com/category/security/feed/"),
    ("Ars Technica", "https://arstechnica.com/security/feed/"),
    ("Wired", "https://www.wired.com/feed/category/security/latest/rss"),
    ("Help Net Security", "https://www.helpnetsecurity.com/feed/"),
    ("Infosecurity Magazine", "https://www.infosecurity-magazine.com/rss/news/"),
    ("Graham Cluley", "https://grahamcluley.com/feed/"),
    ("HackRead", "https://hackread.com/feed/"),
    ("CSO Online", "https://www.csoonline.com/feed/"),
    ("Schneier on Security", "https://www.schneier.com/feed/atom/"),
    ("Troy Hunt", "https://www.troyhunt.com/rss/"),
    ("HIPAA Journal", "https://www.hipaajournal.com/feed/"),
    ("The Cyber Express", "https://thecyberexpress.com/feed/"),
    ("DataBreachToday", "https://www.databreachtoday.com/rssFeeds.php?type=main"),
    ("BankInfoSecurity", "https://www.bankinfosecurity.com/rssFeeds.php?type=main"),
    ("The Guardian", "https://www.theguardian.com/technology/data-computer-security/rss"),
    ("BBC Technology", "https://feeds.bbci.co.uk/news/technology/rss.xml"),
    ("404 Media", "https://www.404media.co/rss/"),
    ("SANS ISC", "https://isc.sans.edu/rssfeed_full.xml"),
    # Vendor research blogs
    ("Malwarebytes Labs", "https://www.malwarebytes.com/blog/feed/index.xml"),
    ("Unit 42", "https://unit42.paloaltonetworks.com/feed/"),
    ("Cisco Talos", "https://blog.talosintelligence.com/rss/"),
    ("Securelist", "https://securelist.com/feed/"),
    ("WeLiveSecurity", "https://www.welivesecurity.com/en/rss/feed/"),
    ("Microsoft Security", "https://www.microsoft.com/en-us/security/blog/feed/"),
    ("SentinelLabs", "https://www.sentinelone.com/labs/feed/"),
    ("Check Point Research", "https://research.checkpoint.com/feed/"),
    ("Tenable", "https://www.tenable.com/blog/feed"),
    ("Qualys", "https://blog.qualys.com/feed"),
    ("Wordfence", "https://www.wordfence.com/feed/"),
    ("Huntress", "https://www.huntress.com/blog/rss.xml"),
    ("watchTowr Labs", "https://labs.watchtowr.com/rss/"),
    ("Project Zero", "https://googleprojectzero.blogspot.com/feeds/posts/default"),
)

ADVISORY_FEEDS: tuple[tuple[str, str], ...] = (
    ("Microsoft MSRC", "https://api.msrc.microsoft.com/update-guide/rss"),
    ("Cisco PSIRT", "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"),
    ("Palo Alto Networks", "https://security.paloaltonetworks.com/rss.xml"),
    ("Fortinet PSIRT", "https://filestore.fortinet.com/fortiguard/rss/ir.xml"),
    ("Chrome Releases", "https://chromereleases.googleblog.com/feeds/posts/default"),
    ("Ubuntu USN", "https://ubuntu.com/security/notices/rss.xml"),
    ("Debian DSA", "https://www.debian.org/security/dsa"),
    ("Arch Linux", "https://security.archlinux.org/advisory/feed.atom"),
    ("Jenkins", "https://www.jenkins.io/security/advisories/rss.xml"),
    ("GitLab", "https://about.gitlab.com/security-releases.xml"),
    ("Node.js", "https://nodejs.org/en/feed/vulnerability.xml"),
    ("Drupal", "https://www.drupal.org/security/rss.xml"),
    ("RustSec", "https://rustsec.org/feed.xml"),
    ("CERT/CC", "https://www.kb.cert.org/vuls/atomfeed/"),
    ("NCSC UK", "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml"),
    ("CERT-FR", "https://www.cert.ssi.gouv.fr/alerte/feed/"),
    ("JPCERT/CC", "https://www.jpcert.or.jp/english/rss/jpcert-en.rdf"),
    ("Canadian Cyber Centre", "https://www.cyber.gc.ca/api/cccs/rss/v1/get?feed=alerts_advisories&lang=en"),
    ("ACSC Australia", "https://www.cyber.gov.au/rss/alerts"),
)

EXPLOIT_FEEDS: tuple[tuple[str, str], ...] = (
    ("Exploit-DB", "https://www.exploit-db.com/rss.xml"),
    ("ZDI published", "https://www.zerodayinitiative.com/rss/published/"),
    ("ZDI upcoming", "https://www.zerodayinitiative.com/rss/upcoming/"),
    ("Full Disclosure", "https://seclists.org/rss/fulldisclosure.rss"),
    ("oss-security", "https://seclists.org/rss/oss-sec.rss"),
    ("CXSecurity", "https://cxsecurity.com/wlb/rss/all/"),
    ("Sploitus", "https://sploitus.com/rss"),
)

FORUM_FEEDS: tuple[tuple[str, str], ...] = (
    ("Lobsters", "https://lobste.rs/t/security.rss"),
    # One combined request: Reddit rate-limits anonymous clients hard.
    ("Reddit", "https://www.reddit.com/r/netsec+cybersecurity+blueteamsec/.rss"),
)

_URGENT_RE = re.compile(r"\b(critical|zero[- ]day|0-?day|actively exploited|exploited in the wild|emergency|RCE|remote code execution)\b", re.I)


def _local(tag: object) -> str:
    return tag.rsplit("}", 1)[-1] if isinstance(tag, str) else ""


def _text(node, *names: str) -> str:
    """First non-empty child text whose tag matches, whatever its namespace."""
    for child in node:
        if _local(child.tag) in names and (child.text or "").strip():
            return child.text
    return ""


def parse_feed(xml_text: str, source: str, tag: str | None = None) -> list[dict]:
    """RSS 2.0, RSS 1.0 (RDF) or Atom -> items.

    With `tag` unset the feed is general news and off-topic headlines are
    dropped; with it set (ADVISORY, EXPLOIT) every entry is kept under that tag.
    """
    root = ET.fromstring(xml_text)
    out = []
    entries = [e for e in root.iter() if _local(e.tag) in ("item", "entry")]
    for e in entries[:80]:
        title = clean(_text(e, "title"), 200)
        link = _text(e, "link")
        if not link.strip():
            for child in e:
                if _local(child.tag) == "link" and child.get("href") and child.get("rel", "alternate") == "alternate":
                    link = child.get("href", "")
                    break
        link = safe_url(link) or safe_url(_text(e, "guid", "id"))
        if not title or not link:
            continue
        summary = clean(_text(e, "description", "summary", "encoded", "content"), 280)
        topic = tag or classify(title) or classify(summary)
        if not topic:
            continue
        ts = rfc822_ts(_text(e, "pubDate")) or iso_ts(_text(e, "updated", "published", "date"))
        urgent = bool(_URGENT_RE.search(title))
        tags = [topic]
        cve = CVE_RE.search(f"{title} {summary}")
        if cve:
            tags.append(cve.group(0))
        out.append(
            {
                "id": f"rss:{link}",
                "ts": ts,
                "ref": source,
                "sev": "critical" if urgent and tag else "high" if urgent or topic in ("BREACH", "EXPLOIT") else "medium",
                "title": title,
                "url": link,
                "summary": "" if summary == title else summary,
                "source": source,
                "tags": tags,
            }
        )
    return out


async def _fetch_feeds(
    client: httpx.AsyncClient, feeds: tuple[tuple[str, str], ...], prefix: str, *, tag: str | None, days: int, cap: int
) -> dict:
    gate = asyncio.Semaphore(12)

    async def one(source: str, url: str) -> list[dict]:
        async with gate:
            resp = await _get(client, url, timeout=20.0)
        return parse_feed(resp.text, source, tag)

    results = await asyncio.gather(*(one(s, u) for s, u in feeds), return_exceptions=True)
    if all(isinstance(r, BaseException) for r in results):
        raise next(r for r in results if isinstance(r, BaseException))
    seen: dict[str, dict] = {}
    titles: set[str] = set()
    failed = []
    now = time.time()
    for (name, _), r in zip(feeds, results):
        if isinstance(r, BaseException):
            failed.append(f"{name} ({_why(r)})")
            continue
        for item in r:
            # Undated entries are treated as new; some advisory feeds omit dates.
            if not item["ts"] or item["ts"] > now + 86400:
                item["ts"] = int(now)
            key = re.sub(r"\W+", "", item["title"].lower())
            if item["id"] in seen or key in titles:
                continue
            seen[item["id"]] = item
            titles.add(key)
    cutoff = now - days * 86400
    items = sorted((i for i in seen.values() if i["ts"] >= cutoff), key=lambda i: i["ts"], reverse=True)
    return {
        "items": items[:cap],
        "stats": {f"{prefix}_feeds_ok": len(feeds) - len(failed), f"{prefix}_feeds": len(feeds)},
        "failed": failed,
    }


async def fetch_wire(client: httpx.AsyncClient) -> dict:
    return await _fetch_feeds(client, NEWS_FEEDS, "wire", tag=None, days=14, cap=400)


async def fetch_advisories(client: httpx.AsyncClient) -> dict:
    return await _fetch_feeds(client, ADVISORY_FEEDS, "advisory", tag="ADVISORY", days=21, cap=400)


async def fetch_exploits(client: httpx.AsyncClient) -> dict:
    return await _fetch_feeds(client, EXPLOIT_FEEDS, "exploit", tag="EXPLOIT", days=21, cap=300)


async def fetch_forums(client: httpx.AsyncClient) -> dict:
    return await _fetch_feeds(client, FORUM_FEEDS, "forum", tag=None, days=7, cap=150)


# --------------------------------------------------------------------------
# Fediverse — links the infosec.exchange crowd is passing around.
# --------------------------------------------------------------------------

FEDI_URL = "https://infosec.exchange/api/v1/trends/links"


async def fetch_fedi(client: httpx.AsyncClient) -> dict:
    rows = (await _get(client, FEDI_URL, params={"limit": 20})).json()
    now = int(time.time())
    items = []
    for r in rows if isinstance(rows, list) else []:
        title = clean(r.get("title"), 200)
        link = safe_url(r.get("url"))
        summary = clean(r.get("description"), 240)
        topic = classify(title) or classify(summary)
        if not title or not link or not topic:
            continue
        history = r.get("history") or [{}]
        try:
            accounts = int((history[0] or {}).get("accounts") or 0)
        except (TypeError, ValueError):
            accounts = 0
        items.append(
            {
                "id": f"fedi:{link}",
                "ts": iso_ts(r.get("published_at")) or now,
                "ref": f"◆ {accounts}",
                "sev": "high" if accounts >= 50 else "medium" if accounts >= 10 else "low",
                "title": title,
                "url": link,
                "summary": summary,
                "source": f"infosec.exchange · {clean(r.get('provider_name'), 60)}".rstrip(" ·"),
                "tags": [topic],
            }
        )
    return {"items": items, "stats": {}}


# --------------------------------------------------------------------------
# ransomware.live — victims named on ransomware leak sites. These are the
# attackers' own claims: labelled as such, never linked to the leak site.
# --------------------------------------------------------------------------

RANSOM_URL = "https://api.ransomware.live/v2/recentvictims"


async def fetch_ransom(client: httpx.AsyncClient) -> dict:
    rows = (await _get(client, RANSOM_URL)).json()
    now = time.time()
    items = []
    for v in rows if isinstance(rows, list) else []:
        if not isinstance(v, dict):
            continue
        victim = clean(v.get("victim") or v.get("post_title"), 120)
        group = clean(v.get("group") or v.get("group_name"), 40)
        if not victim:
            continue
        ts = iso_ts(v.get("discovered")) or iso_ts(v.get("attackdate")) or iso_ts(v.get("published"))
        page = safe_url(v.get("url"))
        if not page or not (httpx.URL(page).host or "").endswith("ransomware.live"):
            page = "https://www.ransomware.live/"
        bits = [f"Named on the {group} leak site." if group else "Named on a ransomware leak site."]
        sector = clean(v.get("activity"), 60)
        country = clean(v.get("country"), 40)
        if sector and sector.lower() != "not found":
            bits.append(f"Sector: {sector}.")
        if country:
            bits.append(f"Country: {country}.")
        bits.append("Attacker's claim, not confirmed by the victim.")
        items.append(
            {
                "id": f"ransom:{group}:{victim}",
                "ts": ts,
                "ref": group or "unknown",
                "sev": "high",
                "title": victim,
                "url": page,
                "summary": " ".join(bits),
                "source": "ransomware.live",
                "tags": ["RANSOMWARE", "CLAIMED"],
            }
        )
    items.sort(key=lambda i: i["ts"], reverse=True)
    return {
        "items": items[:300],
        # The API returns the newest 100 claims, a few days at most, so count a
        # window that is fully covered.
        "stats": {"ransom_claims_24h": sum(1 for i in items if now - i["ts"] < 86400)},
    }


# --------------------------------------------------------------------------
# SEC EDGAR — 8-K filings under Item 1.05, where US-listed companies must
# disclose a material cybersecurity incident. The official "we got hacked".
# --------------------------------------------------------------------------

SEC_URL = "https://efts.sec.gov/LatestSearch/rest/search-index"


async def fetch_sec(client: httpx.AsyncClient) -> dict:
    # SEC's fair-access policy rejects clients that do not identify themselves,
    # so this source only runs when SEC_USER_AGENT ("Name contact@example.com")
    # is configured. See active_sources().
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=120)
    data = (
        await _get(
            client,
            SEC_URL,
            params={
                "q": '"Material Cybersecurity Incidents"',
                "forms": "8-K,8-K/A",
                "dateRange": "custom",
                "startdt": start.strftime("%Y-%m-%d"),
                "enddt": end.strftime("%Y-%m-%d"),
            },
            headers={"User-Agent": settings.sec_user_agent or USER_AGENT},
        )
    ).json()
    seen: dict[str, dict] = {}
    for hit in ((data.get("hits") or {}).get("hits") or []):
        src = hit.get("_source") or {}
        filed_items = src.get("items") or []
        if filed_items and "1.05" not in filed_items:
            continue
        adsh = clean(src.get("adsh"), 30)
        names = src.get("display_names") or []
        ciks = src.get("ciks") or []
        if not adsh or not names or adsh in seen:
            continue
        company = clean(re.sub(r"\s*\(CIK \d+\)", "", str(names[0])), 120)
        filename = str(hit.get("_id", "")).partition(":")[2]
        url = "https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&type=8-K"
        if ciks and str(ciks[0]).isdigit() and re.fullmatch(r"[\w.-]+", filename or ""):
            url = f"https://www.sec.gov/Archives/edgar/data/{int(ciks[0])}/{adsh.replace('-', '')}/{filename}"
        filed = clean(src.get("file_date"), 12)
        form = clean(src.get("form") or src.get("file_type"), 10) or "8-K"
        seen[adsh] = {
            "id": f"sec:{adsh}",
            "ts": iso_ts(filed),
            "ref": "SEC 8-K",
            "sev": "critical",
            "title": company,
            "url": url,
            "summary": f"Filed a {form} on {filed} disclosing a material cybersecurity incident (Item 1.05).",
            "source": "SEC EDGAR",
            "tags": ["BREACH", "DISCLOSED"],
        }
    items = sorted(seen.values(), key=lambda i: i["ts"], reverse=True)
    return {"items": items, "stats": {"sec_8k_120d": len(items)}}


# --------------------------------------------------------------------------
# EPSS — probability a CVE gets exploited in the next 30 days. Not a feed of
# its own: used to annotate CVE rows from the other sources.
# --------------------------------------------------------------------------

EPSS_URL = "https://api.first.org/data/v1/epss"


async def fetch_epss(client: httpx.AsyncClient, cves: list[str]) -> dict[str, float]:
    scores: dict[str, float] = {}
    for i in range(0, len(cves), 80):
        batch = cves[i : i + 80]
        data = (await _get(client, EPSS_URL, params={"cve": ",".join(batch), "limit": len(batch)})).json()
        for row in data.get("data") or []:
            try:
                scores[str(row["cve"])] = float(row["epss"])
            except (KeyError, TypeError, ValueError):
                continue
    return scores


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Source:
    key: str
    label: str
    home: str
    fetch: Callable[[httpx.AsyncClient], Awaitable[dict]]


SOURCES: tuple[Source, ...] = (
    Source("kev", "CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", fetch_kev),
    Source("nvd", "NVD", "https://nvd.nist.gov/", fetch_nvd),
    Source("ghsa", "GitHub Advisories", "https://github.com/advisories", fetch_ghsa),
    Source("advisories", f"Vendor + CERT feeds ({len(ADVISORY_FEEDS)})", "https://www.cisa.gov/news-events/cybersecurity-advisories", fetch_advisories),
    Source("exploits", f"Exploit feeds ({len(EXPLOIT_FEEDS)})", "https://www.exploit-db.com/", fetch_exploits),
    Source("hibp", "Have I Been Pwned", "https://haveibeenpwned.com/PwnedWebsites", fetch_hibp),
    Source("sec", "SEC 8-K Item 1.05", "https://www.sec.gov/edgar/search/", fetch_sec),
    Source("ransom", "ransomware.live", "https://www.ransomware.live/", fetch_ransom),
    Source("wire", f"Security press ({len(NEWS_FEEDS)})", "https://www.bleepingcomputer.com/", fetch_wire),
    Source("hn", "Hacker News", "https://news.ycombinator.com/", fetch_hn),
    Source("forums", "Lobsters + Reddit", "https://lobste.rs/t/security", fetch_forums),
    Source("fedi", "infosec.exchange", "https://infosec.exchange/", fetch_fedi),
)


def active_sources() -> tuple[Source, ...]:
    """Sources that can run with the current configuration."""
    return tuple(s for s in SOURCES if s.key != "sec" or settings.sec_user_agent)


def make_client(transport: httpx.AsyncBaseTransport | None = None) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=TIMEOUT,
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json, application/rss+xml, application/atom+xml, */*;q=0.5"},
        transport=transport,
    )
