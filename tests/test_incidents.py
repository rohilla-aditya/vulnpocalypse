"""Incident detection: names several sources report an attack on."""

import time

from app import incidents

NOW = time.time()


def row(title, source, summary="", age_h=2, tag="BREACH", **extra):
    return {"id": f"{source}:{title}", "ts": int(NOW - age_h * 3600), "title": title, "summary": summary,
            "source": source, "url": f"https://{source.lower().replace(' ', '')}.example/a", "tags": [tag], **extra}


BREACH = [
    row("Jaguar Land Rover Confirms Data Theft After Cyberattack", "The Hacker News"),
    row("Jaguar Land Rover says hackers stole data in August attack", "BleepingComputer",
        "The carmaker Jaguar Land Rover said on Tuesday that attackers took some data.", age_h=1),
    row("JLR production halted: Jaguar Land Rover extends shutdown", "The Register",
        "Suppliers to Jaguar Land Rover are warning of layoffs."),
    row("Hackers Breach PowerSchool, Steal Student Records", "SecurityWeek"),
    row("PowerSchool hack exposes data of millions of students", "TechCrunch", age_h=30),
    row("Initech hit by ransomware", "DataBreaches.net"),  # one source only
    row("Microsoft Confirms Breach of Test Tenant", "Dark Reading", "Microsoft said the tenant was isolated."),
    row("Microsoft customers exposed in breach", "CyberScoop", "A spokesperson for Microsoft declined to comment."),
    row("Ask HN: PowerSchool breach, what now?", "Hacker News", link="https://blog.example/ps"),
    row("Old Acme breach still unresolved", "The Record", "Staff at Acme were told.", age_h=24 * 20),
    row("Acme Breach Lawsuit Filed", "SecurityWeek", age_h=24 * 20),
]
VULN = [
    row("Microsoft patches 80 flaws in November update", "BleepingComputer", "Microsoft fixed two zero-days.", tag="VULN"),
    row("Microsoft Warns of Exploited Windows Bug", "The Hacker News", tag="VULN"),
    row("Critical Microsoft Exchange flaw under attack", "SecurityWeek", tag="VULN"),
]


def test_detects_incidents_named_by_several_sources():
    found = {i["title"]: i for i in incidents.detect(BREACH, VULN, NOW)}
    assert set(found) == {"Jaguar Land Rover", "PowerSchool"}

    jlr = found["Jaguar Land Rover"]  # the full name, not "Jaguar" or "Land Rover"
    assert jlr["ref"] == "3 sources" and jlr["sev"] == "high" and jlr["tags"] == ["ATTACK", "NEW"]
    assert [l["label"] for l in jlr["links"]] == ["BleepingComputer", "The Hacker News", "The Register"]
    assert jlr["summary"].startswith("“Jaguar Land Rover says hackers stole data")  # newest headline

    ps = found["PowerSchool"]
    assert ps["ref"] == "3 sources" and ps["tags"] == ["ATTACK"]  # first report is older than a day
    # The Hacker News row links the article it points at, not the discussion.
    assert {"label": "Hacker News", "url": "https://blog.example/ps"} in ps["links"]


def test_filters():
    titles = {i["title"] for i in incidents.detect(BREACH, VULN, NOW)}
    assert "Initech" not in titles      # a single source is not corroboration
    assert "Microsoft" not in titles    # shows up in patch news as often as breach news: a vendor
    assert "Acme" not in titles         # outside the 7-day window
    assert not any(t in titles for t in ("Confirms", "Hackers", "Data", "Breach"))  # Title Case noise
    assert incidents.detect([], [], NOW) == []


def test_aggregators_alone_do_not_make_an_incident():
    rows = [row("Globex breach megathread", "Hacker News", "People at Globex are upset."), row("Globex breach discussion", "Reddit")]
    assert incidents.detect(rows, [], NOW) == []
