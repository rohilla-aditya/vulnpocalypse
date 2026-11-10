"""Scrapers against canned upstream responses: no network in tests."""

import asyncio
import json
import time
from datetime import datetime, timezone

import httpx

from app import sources
from app.feed import Feed

NOW = int(time.time())
TODAY = datetime.now(timezone.utc).strftime("%Y-%m-%d")

KEV = {
    "vulnerabilities": [
        {"cveID": "CVE-2026-0001", "vendorProject": "Acme", "product": "Router", "vulnerabilityName": "Acme Router RCE",
         "dateAdded": TODAY, "shortDescription": "Bad <b>things</b>.", "dueDate": "2026-12-01", "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2019-0002", "vendorProject": "Old", "product": "Thing", "vulnerabilityName": "Old bug",
         "dateAdded": "2021-11-03", "shortDescription": "x", "knownRansomwareCampaignUse": "Unknown"},
    ]
}
NVD = {
    "totalResults": 1,
    "vulnerabilities": [
        {"cve": {"id": "CVE-2026-9999", "published": "2026-11-09T10:00:00.000", "vulnStatus": "Analyzed",
                 "descriptions": [{"lang": "es", "value": "no"}, {"lang": "en", "value": "Heap overflow in libfoo."}],
                 "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}},
        {"cve": {"id": "CVE-2026-0000", "vulnStatus": "Rejected", "descriptions": []}},
    ],
}
GHSA = [
    {"ghsa_id": "GHSA-aaaa-bbbb-cccc", "cve_id": None, "html_url": "javascript:alert(1)", "summary": "Prototype pollution",
     "severity": "critical", "published_at": "2026-11-09T00:00:00Z", "withdrawn_at": None, "cvss": {"score": 9.1},
     "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "leftpad"}}]},
]
HIBP = [
    {"Name": "MegaCorp", "Title": "MegaCorp", "Domain": "megacorp.example", "BreachDate": "2026-10-01",
     "AddedDate": datetime.fromtimestamp(NOW - 86400, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
     "PwnCount": 12_500_000, "DataClasses": ["Email addresses", "Passwords"],
     "Description": 'In October, <a href="https://x.example">MegaCorp</a> was breached.', "IsVerified": True},
    {"Name": "FakeDump", "Title": "Fake", "AddedDate": "2026-11-01T00:00:00Z", "PwnCount": 5, "IsFabricated": True},
]
HN = {
    "hits": [
        {"objectID": "424242", "title": "MegaCorp hacked, 12M records leaked", "url": "https://news.example/megacorp",
         "points": 612, "num_comments": 300, "created_at_i": NOW - 3600},
        {"objectID": "424243", "title": "Show HN: my todo app", "url": "https://todo.example", "points": 50,
         "num_comments": 2, "created_at_i": NOW - 3600},
    ]
}
RSS = f"""<?xml version="1.0"?><rss version="2.0"><channel><title>x</title>
<item><title>Ransomware gang hits Initech &amp; friends</title><link>https://press.example/initech</link>
<pubDate>{datetime.fromtimestamp(NOW - 7200, timezone.utc).strftime('%a, %d %b %Y %H:%M:%S +0000')}</pubDate>
<description><![CDATA[<p>Initech <script>alert(1)</script> confirmed.</p>]]></description></item>
<item><title>Our favourite keyboards of the year</title><link>https://press.example/kb</link>
<pubDate>Mon, 09 Nov 2026 10:00:00 +0000</pubDate><description>Clicky.</description></item>
<item><title>Leaked data</title><link>javascript:alert(1)</link></item>
</channel></rss>"""
ATOM = f"""<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">
<entry><title>Critical zero-day in WidgetOS exploited</title><link rel="alternate" href="https://reg.example/widget"/>
<updated>{datetime.fromtimestamp(NOW - 600, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}</updated><summary>Patch now.</summary></entry></feed>"""


RANSOM = [
    {"victim": "Initech GmbH", "group": "lockbit3", "discovered": "%s", "country": "DE", "activity": "Manufacturing",
     "claim_url": "http://evil.onion/x", "url": "https://www.ransomware.live/id/abc", "description": "<b>we own you</b>"},
]
SEC = {"hits": {"hits": [
    {"_id": "0001234567-26-000042:acme-8k.htm",
     "_source": {"adsh": "0001234567-26-000042", "ciks": ["0000123456"], "display_names": ["Acme Corp  (ACME)  (CIK 0000123456)"],
                 "file_date": "%s", "form": "8-K", "items": ["1.05", "9.01"]}},
    {"_id": "0009999999-26-000001:other.htm",
     "_source": {"adsh": "0009999999-26-000001", "ciks": ["0000999999"], "display_names": ["Unrelated Inc"],
                 "file_date": "%s", "form": "8-K", "items": ["5.02"]}},
]}}
FEDI = [
    {"url": "https://blog.example/0day", "title": "New zero-day in WidgetOS", "description": "d", "provider_name": "Example Blog",
     "history": [{"accounts": "61", "uses": "80"}]},
    {"url": "https://blog.example/cats", "title": "Cats", "description": "meow", "history": [{"accounts": "9"}]},
]
RDF = """<?xml version="1.0"?><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns="http://purl.org/rss/1.0/"
 xmlns:dc="http://purl.org/dc/elements/1.1/"><item rdf:about="https://deb.example/dsa-1"><title>DSA-1 widget - security update</title>
<link>https://deb.example/dsa-1</link><dc:date>%s</dc:date></item></rdf:RDF>"""
RANSOM[0]["discovered"] = datetime.fromtimestamp(NOW - 3600, timezone.utc).strftime("%Y-%m-%d %H:%M:%S.000000")
SEC["hits"]["hits"][0]["_source"]["file_date"] = TODAY
SEC["hits"]["hits"][1]["_source"]["file_date"] = TODAY
RDF = RDF % datetime.fromtimestamp(NOW - 900, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def handler(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    if host == "www.cisa.gov" and request.url.path.endswith(".json"):
        return httpx.Response(200, json=KEV)
    if host == "services.nvd.nist.gov":
        assert request.url.params["cvssV3Severity"] in ("CRITICAL", "HIGH")
        return httpx.Response(200, json=NVD if request.url.params["cvssV3Severity"] == "CRITICAL" else {"vulnerabilities": []})
    if host == "api.github.com":
        return httpx.Response(200, json=GHSA if request.url.params["severity"] == "critical" else [])
    if host == "haveibeenpwned.com":
        return httpx.Response(200, json=HIBP)
    if host == "hn.algolia.com":
        return httpx.Response(200, json=HN)
    if host == "api.ransomware.live":
        return httpx.Response(200, json=RANSOM)
    if host == "efts.sec.gov":
        assert "@" in request.headers["user-agent"]
        return httpx.Response(200, json=SEC)
    if host == "infosec.exchange":
        return httpx.Response(200, json=FEDI)
    if host == "api.first.org":
        cves = request.url.params["cve"].split(",")
        return httpx.Response(200, json={"data": [{"cve": c, "epss": "0.9423" if c == "CVE-2026-0001" else "0.0004"} for c in cves]})
    if host in ("www.theregister.com", "www.schneier.com"):
        return httpx.Response(200, text=ATOM)
    if host == "www.debian.org":
        return httpx.Response(200, text=RDF)
    if host == "krebsonsecurity.com":
        return httpx.Response(503)
    return httpx.Response(200, text=RSS)


def client(h=handler):
    return sources.make_client(httpx.MockTransport(h))


def run(coro):
    return asyncio.run(coro)


def test_kev():
    out = run(sources.fetch_kev(client()))
    first = out["items"][0]
    assert first["ref"] == "CVE-2026-0001" and first["sev"] == "critical"
    assert "RANSOMWARE" in first["tags"] and "FIX BY 2026-12-01" in first["tags"]
    assert "<" not in first["summary"] and first["summary"].startswith("Bad things")
    assert out["stats"] == {"kev_total": 2, "kev_ransomware": 1, "kev_30d": 1}


def test_nvd_skips_rejected_and_reads_score():
    out = run(sources.fetch_nvd(client()))
    assert [i["ref"] for i in out["items"]] == ["CVE-2026-9999"]
    assert out["items"][0]["tags"] == ["CVSS 9.8"]
    assert out["items"][0]["title"] == "Heap overflow in libfoo."


def test_ghsa_rejects_non_http_url():
    item = run(sources.fetch_ghsa(client()))["items"][0]
    assert item["url"] == "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"
    assert item["summary"] == "npm:leftpad"


def test_hibp_skips_fabricated_and_strips_html():
    out = run(sources.fetch_hibp(client()))
    assert [i["title"] for i in out["items"]] == ["MegaCorp"]
    item = out["items"][0]
    assert item["ref"] == "12.5M accts" and item["sev"] == "critical"
    assert "<" not in item["summary"] and "Passwords" in item["summary"]
    assert out["stats"]["accounts_365d"] == 12_500_000


def test_hn_keeps_only_on_topic_and_dedupes():
    out = run(sources.fetch_hn(client()))
    assert len(out["items"]) == 1
    item = out["items"][0]
    assert item["url"] == "https://news.ycombinator.com/item?id=424242"
    assert item["link"] == "https://news.example/megacorp" and item["tags"] == ["BREACH"]


def test_wire_parses_rss_and_atom_and_survives_a_dead_feed():
    out = run(sources.fetch_wire(client()))
    titles = [i["title"] for i in out["items"]]
    assert titles == ["Critical zero-day in WidgetOS exploited", "Ransomware gang hits Initech & friends"]
    assert out["items"][1]["tags"] == ["BREACH"] and out["items"][0]["tags"] == ["VULN"]
    assert out["items"][0]["sev"] == "high"  # urgent wording bumps a news row
    assert "<" not in out["items"][1]["summary"]
    assert out["stats"]["wire_feeds_ok"] == len(sources.NEWS_FEEDS) - 1
    assert out["failed"] == ["Krebs on Security (HTTP 503)"]


def test_advisory_and_exploit_feeds_keep_every_entry_and_read_rdf():
    adv = run(sources.fetch_advisories(client()))
    titles = {i["title"]: i for i in adv["items"]}
    assert "DSA-1 widget - security update" in titles  # RSS 1.0 / RDF, namespaced
    assert "Our favourite keyboards of the year" in titles  # no topic filter on advisory feeds
    assert all(i["tags"][0] == "ADVISORY" for i in adv["items"])
    exp = run(sources.fetch_exploits(client()))
    assert exp["items"] and all(i["tags"][0] == "EXPLOIT" for i in exp["items"])
    assert all(i["url"].startswith("https://") for i in adv["items"] + exp["items"])


def test_ransomware_claims_are_labelled_and_never_link_the_leak_site():
    out = run(sources.fetch_ransom(client()))
    item = out["items"][0]
    assert item["title"] == "Initech GmbH" and item["ref"] == "lockbit3"
    assert item["tags"] == ["RANSOMWARE", "CLAIMED"] and "not confirmed" in item["summary"]
    assert item["url"] == "https://www.ransomware.live/id/abc"
    assert "onion" not in str(item) and "we own you" not in str(item)
    assert out["stats"]["ransom_claims_24h"] == 1


def test_sec_keeps_only_item_105_filings(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "sec_user_agent", "Example Dashboard ops@example.com")
    out = run(sources.fetch_sec(client()))
    assert [i["title"] for i in out["items"]] == ["Acme Corp (ACME)"]
    assert out["items"][0]["url"] == "https://www.sec.gov/Archives/edgar/data/123456/000123456726000042/acme-8k.htm"


def test_fedi_trends_filtered_to_topic():
    out = run(sources.fetch_fedi(client()))
    assert [i["title"] for i in out["items"]] == ["New zero-day in WidgetOS"]
    assert out["items"][0]["ref"] == "◆ 61" and out["items"][0]["sev"] == "high"


def test_xml_bombs_are_refused():
    bomb = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><rss><channel><item><title>&a;</title></item></channel></rss>'
    try:
        sources.parse_feed(bomb, "x")
    except Exception as exc:
        assert "Entities" in type(exc).__name__ or "Forbidden" in type(exc).__name__
    else:
        raise AssertionError("entity declaration was accepted")


def test_feed_keeps_last_good_copy_when_a_source_dies(tmp_path, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "cache_file", tmp_path / "cache.json")
    assert "sec" not in [s.key for s in Feed().sources]  # off until a contact User-Agent is configured
    monkeypatch.setattr(settings, "sec_user_agent", "Example Dashboard ops@example.com")
    f = Feed()
    run(f.refresh(client()))
    p = f.payload()
    assert [t["key"] for t in p["tabs"]] == ["exploited", "cves", "advisories", "exploits", "pwned", "ransom", "wire", "chatter", "watchlist"]
    assert {i["ref"] for i in p["tabs"][1]["items"]} == {"CVE-2026-9999", "GHSA-aaaa-bbbb-cccc"}
    assert all(s["ok"] for s in p["sources"]), [s for s in p["sources"] if not s["ok"]]
    assert {i["source"] for i in p["tabs"][4]["items"]} == {"megacorp.example", "SEC EDGAR"}
    assert all(t["items"] for t in p["tabs"][:8])
    # EPSS annotation: scored rows get a tag, negligible scores do not.
    kev_rows = {i["ref"]: i for i in p["tabs"][0]["items"]}
    assert "EPSS 94%" in kev_rows["CVE-2026-0001"]["tags"]
    assert not any(t.startswith("EPSS") for t in kev_rows["CVE-2019-0002"]["tags"])
    wire = next(s for s in p["sources"] if s["key"] == "wire")
    assert wire["failed"] == ["Krebs on Security (HTTP 503)"]

    def kev_down(request):
        return httpx.Response(500) if request.url.path.endswith("known_exploited_vulnerabilities.json") else handler(request)

    run(f.refresh(client(kev_down)))
    p = f.payload()
    kev = next(s for s in p["sources"] if s["key"] == "kev")
    assert kev["ok"] is False and kev["error"] == "HTTP 500" and kev["count"] == 2
    assert p["stats"]["kev_total"] == 2

    # A restart picks the cache back up.
    g = Feed()
    g.load()
    assert g.payload()["tabs"][0]["items"][0]["ref"] == "CVE-2026-0001"
    json.dumps(g.payload())


def test_watchlist_matches_whole_words_and_reads_the_config(tmp_path):
    cfg = tmp_path / "watchlist.json"
    cfg.write_text(json.dumps([{"name": "fire base!", "match": ["Firebase", "firestore"]}, {"name": "", "match": ["x"]}, "junk"]))
    wl = sources.load_watchlist(cfg)
    assert [(name, terms) for name, terms, _ in wl] == [("FIREBASE", ("firebase", "firestore"))]
    assert sources.watch_topics({"title": "Misconfigured Firebase leaks 2M users"}, wl) == ["FIREBASE"]
    assert sources.watch_topics({"title": "x", "summary": "open Firestore rules"}, wl) == ["FIREBASE"]
    assert sources.watch_topics({"title": "Campfirebase camping gear"}, wl) == []
    assert sources.load_watchlist(tmp_path / "missing.json") == []
    assert sources.WATCHLIST, "the shipped watchlist.json must load"


def test_watchlist_tab_collects_rows_from_every_feed(tmp_path, monkeypatch):
    from app import feed as feed_mod
    from app.config import settings

    monkeypatch.setattr(settings, "cache_file", tmp_path / "cache.json")
    wl = [("INITECH", ("initech",), sources.re.compile(r"(?<!\\w)initech(?!\\w)", sources.re.I))]
    monkeypatch.setattr(sources, "WATCHLIST", wl)
    monkeypatch.setattr(feed_mod, "WATCHLIST", wl)
    f = Feed()
    run(f.refresh(client()))
    p = f.payload()
    tab = p["tabs"][-1]
    assert tab["key"] == "watchlist" and p["watchlist"] == ["INITECH"]
    # The ransomware claim and the press headline both name the topic.
    assert {i["id"].split(":")[0] for i in tab["items"]} == {"ransom", "rss"}
    assert all(i["tags"][0] == "INITECH" for i in tab["items"])
    # The original rows are not retagged.
    assert all("INITECH" not in i["tags"] for i in p["tabs"][5]["items"])
