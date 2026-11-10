"""Attacks in the news: incidents detected from what outlets are reporting.

No list of topics to maintain. Every scrape, the breach headlines from the
press, Hacker News, the forums and the fediverse are compared, and a name that
several independent sources are reporting an attack on becomes a row: the
victim (or the crew behind it), who is reporting it, and links to each story.

It is a heuristic, not a language model:

1. Only headlines about an attack count; ones about a flaw or a patch do not.
2. Candidate names are runs of capitalised words. Each needs an "anchor": a
   word that never appears in lower case anywhere in the scraped text, or is
   spelled like a name (PowerSchool, 23andMe). That is what separates
   "Initech" from "Systems" in a Title Case Headline.
3. A name must be in the headlines of MIN_SOURCES sources, one a real outlet.
4. The longest form wins ("Jaguar Land Rover" over "Jaguar"), and names that
   show up in vulnerability stories at least as often are dropped: those are
   vendors and products, not victims.
"""

from __future__ import annotations

import re
import time
from collections import Counter, defaultdict

MIN_SOURCES = 2
WINDOW_DAYS = 7
MAX_NGRAM = 4
MAX_INCIDENTS = 60

_TOKEN_RE = re.compile(r"[^\W_][\w&.+'’-]*")
# A headline about a weakness rather than about someone getting hit.
_VULN_STORY_RE = re.compile(
    r"\b(CVE-\d{4}-\d+|vulnerabilit\w+|flaws?|bugs?|patch\w*|zero[- ]days?|0-?days?|exploit\w*|RCE|PoC|advisor(?:y|ies)|update[sd]?)\b", re.I
)
_SENTENCE_END = (".", "!", "?", ":", ";", "—", "–", "|", '"', "”", "“", "(", "-")
_CONNECT = {"of", "&"}

# Capitalised in prose but never the subject of an incident: places, peoples,
# agencies, calendar words, platforms everyone runs, security vocabulary and
# acronyms, and the outlets themselves.
STOP = set(
    """
    us usa uk eu un u.s u.s. u.k america american americans british britain england english europe european europeans
    china chinese russia russian russians ukraine ukrainian iran iranian israel israeli north south korea korean koreans
    india indian japan japanese germany german france french canada canadian australia australian brazil brazilian
    spain spanish italy italian dutch netherlands poland polish swedish sweden norway finland denmark ireland irish
    asia asian africa african middle east western eastern london washington california texas florida york new
    monday tuesday wednesday thursday friday saturday sunday january february march april may june july august
    september october november december q1 q2 q3 q4 black cyber christmas
    fbi cisa nsa cia doj sec ftc fcc ico nist mitre europol interpol nhs hhs dhs irs gchq ncsc pentagon congress senate
    white house treasury justice department government governments federal state states police court judge ministry
    president trump biden ceo cto ciso cfo cio
    windows linux android ios macos chrome firefox safari edge office outlook exchange sharepoint teams azure aws gcp
    cloud wordpress telegram whatsapp discord youtube facebook instagram tiktok twitter x linkedin reddit github gitlab
    npm pypi docker kubernetes active directory internet web dark darknet tor bitcoin crypto ethereum blockchain python
    java javascript php sql api apis ai llm llms gpt saas iot ot it os pc sms url dns vpn vpns rdp ssh ssl tls http https
    usb sim mfa 2fa sso otp pii phi gdpr hipaa ccpa soc edr xdr siem ics scada
    cve cves cvss kev epss rce xss csrf ssrf lpe dos ddos apt apts poc pocs ttps iocs c2 mitm bec raas
    zero-day zero day 0-day 0day patch tuesday update updates security cybersecurity infosec breach breaches data hack
    hacked hacker hackers hacking attack attacks attacker attackers cyberattack cyberattacks ransomware malware phishing
    leak leaks leaked stolen exposed exposes vulnerability vulnerabilities exploit exploits exploited flaw flaws bug bugs
    million billion thousand customers users accounts records report reports week weekly daily news review roundup
    podcast episode newsletter brief briefing recap digest part edition video webinar sponsored opinion analysis
    how why what when who where the a an this that these those and or but for from with after over into amid via
    inc ltd llc corp co group company companies firm firms giant maker provider vendor vendors bank banks hospital
    hospitals university school schools city county airport airline airlines retailer insurer
    threat threats intelligence research researchers labs lab team teams unit talos mandiant advisory alert alerts
    critical infrastructure system systems service services network networks server servers email emails mobile
    app apps software hardware device devices platform platforms tool tools code source open public private key keys
    agent agents model models operation operations campaign campaigns scam scams fraud alleged allegedly breaking
    exclusive updated live watch inside behind top best first last latest more less big major massive global national
    health healthcare medical financial energy retail education tech technology technologies digital online
    settlement lawsuit class action fine fined ransom extortion incident incidents notification notice
    hit hits says said say warns warn warned confirms confirm confirmed admits admit discloses disclose disclosed
    reveals reveal revealed halts halt halted probes probe investigates investigating investigation suffers suffer
    suffered faces face blames blame denies deny claims claim claimed targets target targeted targeting steals steal
    stole breached disrupts disrupt disrupted shuts shut forces force forced takes take took impacts impact impacted
    affects affect affected exposing leaking hitting linked tied behind arrested arrest charged sentenced pleads
    guilty seized seizes takedown down offline outage restores resumes recovers pays paid refuses demands demand
    notifies notifying begins starts ends continues extends expands grows rises surges drops falls jumps
    another again still now today yesterday here there after before during amid following despite
    production customer employee employees staff student students patient patients people personal information
    details numbers passwords credentials files documents records database databases servers website websites
    thousands millions hundreds dozens several multiple many nearly almost about around
    gang gangs crew actor actors nation-state state-sponsored hacktivist hacktivists criminals cybercriminals
    """.split()
)

# Not counted as independent sources: they only relay what others published.
_AGGREGATORS = ("Hacker News", "Lobsters", "Reddit", "infosec.exchange")


def _clean_token(tok: str) -> str:
    tok = tok.strip(".,:;!?'’\"")
    for suffix in ("'s", "’s"):
        if tok.endswith(suffix):
            tok = tok[: -len(suffix)]
    return tok


def _capitalised(tok: str) -> bool:
    # Digit-led names need real letters behind them: 23andMe yes, 133M and 6.3B no.
    return tok[:1].isupper() or (tok[:1].isdigit() and any(c.isupper() for c in tok) and sum(c.isalpha() for c in tok) >= 3)


def _distinctive(tok: str) -> bool:
    """Reads as a name on spelling alone: PowerSchool, 23andMe, AT&T."""
    if len(tok) < 3 or "-" in tok:
        return False
    inner_caps = any(c.isupper() for c in tok[1:]) and any(c.islower() for c in tok)
    mixed_digits = any(c.isdigit() for c in tok) and any(c.isupper() for c in tok) and sum(c.isalpha() for c in tok) >= 3
    return inner_caps or mixed_digits or "&" in tok


def _is_title_case(words: list[str]) -> bool:
    long_words = [w for w in words if len(w) > 3 and w[0].isalpha()]
    if len(long_words) < 3:
        return True  # too short to tell: treat capitalisation as unreliable
    return sum(1 for w in long_words if w[0].isupper()) / len(long_words) >= 0.6


def _vocabulary(texts: list[str]) -> set[str]:
    """Every word seen written in lower case: ordinary words, not names."""
    vocab: set[str] = set()
    for text in texts:
        for tok in _TOKEN_RE.findall(text):
            tok = _clean_token(tok)
            if tok[:1].islower():
                vocab.add(tok)
                vocab.update(part for part in tok.split("-") if part)
    return vocab


def _common(word: str, vocab: set[str]) -> bool:
    """An ordinary word: stop-listed, or seen in lower case, in this or a simpler inflection."""
    forms = {word}
    for suffix in ("s", "es", "ed", "d", "ing", "ly", "er", "ers"):
        if word.endswith(suffix) and len(word) - len(suffix) >= 3:
            stem = word[: -len(suffix)]
            forms.update({stem, stem + "e"})
    return any(f in STOP or f in vocab for f in forms)


def _candidates(title: str, vocab: set[str]) -> set[tuple[str, ...]]:
    """Name n-grams found in one headline."""
    tokens = [t for t in (_clean_token(t) for t in _TOKEN_RE.findall(title)) if t]
    sentence_case = not _is_title_case(title.split())

    def anchor(tok: str) -> bool:
        low = tok.lower()
        if low in STOP or len(tok) < 2 or not _capitalised(tok):
            return False
        if _distinctive(tok):
            return True
        return not any(_common(part, vocab) for part in low.split("-"))

    def soft(i: int) -> bool:
        # Mid-sentence capitals mean something only when the headline is not Title Case.
        tok = tokens[i]
        return sentence_case and i > 0 and _capitalised(tok) and tok.lower() not in STOP and len(tok) > 1

    runs: list[list[tuple[str, bool]]] = []
    run: list[tuple[str, bool]] = []
    for i, tok in enumerate(tokens):
        is_anchor = anchor(tok)
        if is_anchor or soft(i):
            run.append((tok, is_anchor))
        elif run and tok.lower() in _CONNECT and i + 1 < len(tokens) and (anchor(tokens[i + 1]) or soft(i + 1)):
            run.append((tok, False))
        else:
            if run:
                runs.append(run)
            run = []
    if run:
        runs.append(run)

    grams: set[tuple[str, ...]] = set()
    for run in runs:
        for n in range(1, min(MAX_NGRAM, len(run)) + 1):
            for start in range(len(run) - n + 1):
                gram = run[start : start + n]
                if gram[0][0].lower() in _CONNECT or gram[-1][0].lower() in _CONNECT:
                    continue
                if any(is_anchor for _, is_anchor in gram):
                    grams.add(tuple(tok.lower() for tok, _ in gram))
    return grams


def _contains(longer: tuple[str, ...], shorter: tuple[str, ...]) -> bool:
    n = len(shorter)
    return any(longer[i : i + n] == shorter for i in range(len(longer) - n + 1))


def _origin(item: dict) -> str:
    return str(item.get("source", "")).split(" · ")[0]


def _matcher(gram: tuple[str, ...]) -> re.Pattern:
    return re.compile(r"(?<!\w)" + r"\W+".join(re.escape(g) for g in gram) + r"(?!\w)", re.I)


def detect(
    breach_rows: list[dict], vuln_rows: list[dict], now: float | None = None, extra_texts: tuple[str, ...] | list[str] = ()
) -> list[dict]:
    """Rows for the incidents tab, newest report first."""
    now = now or time.time()
    cutoff = now - WINDOW_DAYS * 86400
    everything = breach_rows + vuln_rows
    # A "breach" headline that is really about a flaw belongs with the vulnerability stories.
    attack_rows = [r for r in breach_rows if r.get("title") and not _VULN_STORY_RE.search(r["title"])]
    vuln_titles = [r.get("title", "") for r in everything if r not in attack_rows]
    rows = [r for r in attack_rows if r.get("ts", 0) >= cutoff]
    if not rows:
        return []

    # The more ordinary prose the vocabulary is built from, the fewer ordinary words pass as names.
    vocab = _vocabulary(
        [r.get("title", "") for r in everything] + [r.get("summary", "") for r in everything] + list(extra_texts)
    )
    grams = {g for row in rows for g in _candidates(row["title"], vocab)}

    # A name's backing is every headline that contains it, however it was capitalised there.
    mentions: dict[tuple[str, ...], list[dict]] = {}
    spelling: dict[tuple[str, ...], Counter] = defaultdict(Counter)
    for gram in grams:
        pattern = _matcher(gram)
        hits = []
        for row in rows:
            match = pattern.search(row["title"])
            if match:
                hits.append(row)
                spelling[gram][match.group(0)] += 1
        mentions[gram] = hits

    def backing(gram: tuple[str, ...]) -> set[str]:
        return {_origin(r) for r in mentions[gram]}

    def press(gram: tuple[str, ...]) -> set[str]:
        return backing(gram) - set(_AGGREGATORS)

    # Enough sources, and at least one of them an actual outlet.
    kept = [g for g in grams if len(backing(g)) >= MIN_SOURCES and press(g)]

    # Vendors and products appear in patch stories at least as often as in attack stories.
    def vuln_hits(gram: tuple[str, ...]) -> int:
        pattern = _matcher(gram)
        return sum(1 for t in vuln_titles if pattern.search(t))

    kept = [g for g in kept if vuln_hits(g) < len(mentions[g])]

    # Longest name wins when it has most of the same backing.
    kept.sort(key=lambda g: (-len(g), -len(backing(g)), g))
    final: list[tuple[str, ...]] = []
    for gram in kept:
        if any(_contains(big, gram) and len(backing(big)) >= 0.6 * len(backing(gram)) for big in final):
            continue
        final.append(gram)

    # Two names backed by exactly the same stories are one incident (victim + attacker).
    by_stories: dict[frozenset, list[tuple[str, ...]]] = defaultdict(list)
    for gram in final:
        by_stories[frozenset(r["id"] for r in mentions[gram])].append(gram)

    out = []
    for grams_ in by_stories.values():
        gram = grams_[0]
        stories = sorted(mentions[gram], key=lambda r: r.get("ts", 0), reverse=True)
        names = [spelling[g].most_common(1)[0][0] for g in grams_[:3]]
        sources = sorted(backing(gram))
        latest, first = stories[0], stories[-1]
        # One link per source, newest story from each.
        links, seen = [], set()
        for s in stories:
            origin = _origin(s)
            if origin in seen:
                continue
            seen.add(origin)
            links.append({"label": origin, "url": s.get("link") or s.get("url", "")})
        n = len(sources)
        tags = ["ATTACK"]
        if now - first.get("ts", 0) < 86400:
            tags.append("NEW")
        out.append(
            {
                "id": "incident:" + "+".join(" ".join(g) for g in grams_),
                "ts": latest.get("ts", 0),
                "ref": f"{n} sources",
                "sev": "critical" if n >= 6 else "high" if n >= 3 else "medium",
                "title": " / ".join(names),
                "url": latest.get("link") or latest.get("url", ""),
                "summary": f"“{latest['title']}” ({_origin(latest)})",
                "source": f"{len(stories)} stories",
                "tags": tags,
                "links": links[:8],
            }
        )
    out.sort(key=lambda i: i["ts"], reverse=True)
    return out[:MAX_INCIDENTS]
