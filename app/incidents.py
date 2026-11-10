"""Attacks in the news: incidents detected from what outlets are reporting.

No list of topics to maintain. Every scrape, the breach headlines from the
press, Hacker News, the forums and the fediverse are compared, and a name that
several independent sources are reporting an attack on becomes a row: the
victim (or the crew behind it), who is reporting it, and links to each story.

It is a heuristic, not a language model:

1. Pull candidate names out of each headline: runs of capitalised words.
2. Keep only words that are also capitalised in the middle of ordinary
   prose somewhere in the corpus (summaries, sentence-case headlines). That is
   what separates "Initech" from "Confirms" in a Title Case Headline.
3. Count distinct sources per name; a name needs MIN_SOURCES of them.
4. Prefer the longest name with the same backing ("Jaguar Land Rover" over
   "Jaguar"), and drop names that show up at least as often in vulnerability
   stories, which are vendors and products rather than victims.
"""

from __future__ import annotations

import re
import time
from collections import Counter, defaultdict

MIN_SOURCES = 2
WINDOW_DAYS = 7
MAX_NGRAM = 4
MAX_INCIDENTS = 60

_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9&.+'’-]*")
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
    return tok[:1].isupper() or (tok[:1].isdigit() and any(c.isalpha() for c in tok))


def _distinctive(tok: str) -> bool:
    """Reads as a name on spelling alone: PowerSchool, 23andMe, AT&T."""
    if len(tok) < 3:
        return False
    inner_caps = any(c.isupper() for c in tok[1:]) and any(c.islower() for c in tok)
    mixed_digits = any(c.isdigit() for c in tok) and any(c.isalpha() for c in tok)
    return inner_caps or mixed_digits or "&" in tok


def _is_title_case(words: list[str]) -> bool:
    long_words = [w for w in words if len(w) > 3 and w[0].isalpha()]
    if len(long_words) < 3:
        return True  # too short to tell: treat as unreliable
    return sum(1 for w in long_words if w[0].isupper()) / len(long_words) >= 0.6


def _proper_nouns(texts: list[str]) -> set[str]:
    """Lower-cased words seen capitalised mid-sentence in ordinary prose."""
    proper: set[str] = set()
    for text in texts:
        words = text.split()
        if _is_title_case(words):
            continue
        for prev, word in zip(words, words[1:]):
            if prev.endswith(_SENTENCE_END):
                continue
            tok = _clean_token(word)
            if tok and tok[0].isupper() and _TOKEN_RE.fullmatch(tok):
                proper.add(tok.lower())
    return proper


def _candidates(title: str, proper: set[str]) -> set[tuple[str, ...]]:
    """Name n-grams found in one headline."""
    tokens = [_clean_token(t) for t in _TOKEN_RE.findall(title)]
    tokens = [t for t in tokens if t]

    def is_name(i: int) -> bool:
        tok = tokens[i]
        low = tok.lower()
        if low in STOP or not _capitalised(tok) or len(tok) < 2:
            return False
        if _distinctive(tok):
            return True
        return low in proper

    runs: list[list[str]] = []
    run: list[str] = []
    for i, tok in enumerate(tokens):
        if is_name(i):
            run.append(tok)
        elif run and tok.lower() in _CONNECT and i + 1 < len(tokens) and is_name(i + 1):
            run.append(tok)
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
                if gram[0].lower() in _CONNECT or gram[-1].lower() in _CONNECT:
                    continue
                grams.add(tuple(g.lower() for g in gram))
    return grams


def _contains(longer: tuple[str, ...], shorter: tuple[str, ...]) -> bool:
    n = len(shorter)
    return any(longer[i : i + n] == shorter for i in range(len(longer) - n + 1))


def _origin(item: dict) -> str:
    return str(item.get("source", "")).split(" · ")[0]


def detect(breach_rows: list[dict], vuln_rows: list[dict], now: float | None = None) -> list[dict]:
    """Rows for the incidents tab, newest report first."""
    now = now or time.time()
    cutoff = now - WINDOW_DAYS * 86400
    rows = [r for r in breach_rows if r.get("ts", 0) >= cutoff and r.get("title")]
    if not rows:
        return []

    prose = [r.get("summary", "") for r in breach_rows + vuln_rows] + [r.get("title", "") for r in breach_rows + vuln_rows]
    proper = _proper_nouns([p for p in prose if p])

    mentions: dict[tuple[str, ...], list[dict]] = defaultdict(list)
    spelling: dict[tuple[str, ...], Counter] = defaultdict(Counter)
    for row in rows:
        title = row["title"]
        for gram in _candidates(title, proper):
            mentions[gram].append(row)
            match = re.search(r"(?<!\w)" + r"\W+".join(re.escape(g) for g in gram) + r"(?!\w)", title, re.I)
            if match:
                spelling[gram][match.group(0)] += 1

    def press(gram: tuple[str, ...]) -> set[str]:
        return {_origin(r) for r in mentions[gram] if _origin(r) not in _AGGREGATORS}

    def backing(gram: tuple[str, ...]) -> set[str]:
        return {_origin(r) for r in mentions[gram]}

    # Enough sources, and at least one of them an actual outlet.
    kept = [g for g in mentions if len(backing(g)) >= MIN_SOURCES and press(g)]

    # Vendors and products appear in patch stories at least as often as in breach stories.
    vuln_titles = [v.get("title", "").lower() for v in vuln_rows]

    def vuln_hits(gram: tuple[str, ...]) -> int:
        pattern = re.compile(r"(?<!\w)" + r"\W+".join(re.escape(g) for g in gram) + r"(?!\w)")
        return sum(1 for t in vuln_titles if pattern.search(t))

    kept = [g for g in kept if vuln_hits(g) < len(mentions[g])]

    # Longest name wins when it has most of the same backing.
    kept.sort(key=lambda g: (-len(g), -len(backing(g))))
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
    for grams in by_stories.values():
        gram = grams[0]
        stories = sorted(mentions[gram], key=lambda r: r.get("ts", 0), reverse=True)
        names = [spelling[g].most_common(1)[0][0] if spelling[g] else " ".join(g).title() for g in grams[:3]]
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
                "id": "incident:" + "+".join(" ".join(g) for g in grams),
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
