// VULN-POCALYPSE NOW — client. Polls feed.json (relative, so the page works from
// a sub-path such as GitHub Pages) and renders rows.
// Everything scraped is rendered with textContent; URLs are re-checked here.
(() => {
  "use strict";

  const POLL_MS = 5 * 60 * 1000;
  const PAGE = 60;
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  };

  const state = { data: null, tab: "exploited", q: "", shown: PAGE };

  // ---- helpers ----------------------------------------------------------
  const pad = (n) => String(n).padStart(2, "0");
  const ymd = (ts) => {
    if (!ts) return "----------";
    const d = new Date(ts * 1000);
    return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
  };
  const ago = (ts) => {
    if (!ts) return "never";
    const s = Math.max(0, Math.floor(Date.now() / 1000 - ts));
    if (s < 90) return `${s}s ago`;
    if (s < 5400) return `${Math.round(s / 60)}m ago`;
    if (s < 172800) return `${Math.round(s / 3600)}h ago`;
    return `${Math.round(s / 86400)}d ago`;
  };
  const human = (n) => {
    if (typeof n !== "number") return "—";
    if (n >= 1e9) return (n / 1e9).toFixed(1).replace(/\.0$/, "") + "B";
    if (n >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, "") + "M";
    if (n >= 1e4) return (n / 1e3).toFixed(1).replace(/\.0$/, "") + "K";
    return n.toLocaleString("en-US");
  };
  const safeHref = (u) => (typeof u === "string" && /^https?:\/\//i.test(u) ? u : null);
  const link = (text, href, cls) => {
    const ok = safeHref(href);
    const a = el(ok ? "a" : "span", cls, text);
    if (ok) {
      a.href = ok;
      a.target = "_blank";
      a.rel = "noopener noreferrer nofollow";
    }
    return a;
  };

  // ---- rendering --------------------------------------------------------
  function renderStats(d) {
    const s = d.stats || {};
    const count = (key) => (d.tabs.find((t) => t.key === key) || { items: [] }).items.length;
    const tiles = [
      ["exploited in the wild", human(s.kev_total), `+${s.kev_30d ?? "?"} in the last 30d`, true],
      ["used by ransomware", human(s.kev_ransomware), "of the exploited set", true],
      ["critical CVEs / 7d", human(s.nvd_critical_7d), `+${human(s.nvd_high_3d)} high in the last 3d`, false],
      ["public exploits / 21d", human(count("exploits")), `${s.exploit_feeds_ok ?? "?"}/${s.exploit_feeds ?? "?"} feeds answering`, false],
      ["accounts pwned / 365d", human(s.accounts_365d), `${s.breaches_365d ?? "?"} breaches catalogued`, true],
      ["ransomware claims / 24h", human(s.ransom_claims_24h), "victims named on leak sites", true],
      ["advisories / 21d", human(count("advisories")), `${s.advisory_feeds_ok ?? "?"}/${s.advisory_feeds ?? "?"} vendors + CERTs answering`, false],
      ["breach headlines / 14d", human(count("wire")), `${s.wire_feeds_ok ?? "?"}/${s.wire_feeds ?? "?"} outlets answering`, false],
    ];
    const box = $("stats");
    box.replaceChildren(
      ...tiles.map(([label, value, sub, hot]) => {
        const t = el("div", "stat" + (hot ? " hot" : ""));
        t.dataset.label = label;
        t.append(el("b", null, value), el("small", null, sub));
        return t;
      })
    );
  }

  function renderTabs(d) {
    $("tabs").replaceChildren(
      ...d.tabs.map((t, i) => {
        const b = el("button", "tab");
        b.type = "button";
        b.setAttribute("role", "tab");
        b.setAttribute("aria-selected", String(t.key === state.tab));
        b.append(`[${i + 1}] ${t.label} `, el("span", "n", `(${t.items.length})`));
        b.addEventListener("click", () => setTab(t.key));
        return b;
      })
    );
  }

  function row(item) {
    const sev = ["critical", "high", "medium", "low"].includes(item.sev) ? item.sev : "none";
    const r = el("article", `row sev-${sev}`);
    r.append(el("div", "date", ymd(item.ts)), el("div", "ref", item.ref || ""));
    const body = el("div", "body");
    body.append(link(item.title || "(untitled)", item.url, "headline"));
    if (item.summary) body.append(el("div", "summary", item.summary));
    const meta = el("div", "meta");
    for (const t of item.tags || []) meta.append(el("span", `tag t-${String(t).split(" ")[0].replace(/[^A-Z]/g, "")}`, t));
    if (item.source && item.source !== item.ref) meta.append(el("span", null, item.source));
    if (item.link) meta.append(" → ", link("article", item.link));
    body.append(meta);
    r.append(body);
    return r;
  }

  function renderList() {
    const d = state.data;
    const list = $("list");
    if (!d) return;
    const tab = d.tabs.find((t) => t.key === state.tab) || d.tabs[0];
    const q = state.q.trim().toLowerCase();
    const hay = (i) => `${i.ref} ${i.title} ${i.summary} ${i.source} ${(i.tags || []).join(" ")}`.toLowerCase();
    const items = q ? tab.items.filter((i) => hay(i).includes(q)) : tab.items;
    // grep searches every feed: the count per tab shows where the hits are.
    const total = q ? d.tabs.reduce((n, t) => n + t.items.filter((i) => hay(i).includes(q)).length, 0) : 0;
    $("matches").textContent = q ? `${items.length} here / ${total} in all feeds` : "";
    document.querySelectorAll("#tabs .tab").forEach((b, idx) => {
      const t = d.tabs[idx];
      const n = q ? t.items.filter((i) => hay(i).includes(q)).length : t.items.length;
      b.querySelector(".n").textContent = `(${n})`;
      b.classList.toggle("nohit", Boolean(q) && n === 0);
    });

    if (!items.length) {
      const msg = !d.generated_at
        ? "[ .... ] first scrape in progress, hang tight"
        : q
        ? `grep: no matches for '${state.q}' in ${tab.label.toLowerCase()}`
        : "[ WARN ] this feed returned nothing on the last scrape";
      const p = el("p", "dim empty", msg);
      if (!d.generated_at) p.append(el("span", "cursor", "█"));
      list.replaceChildren(p);
      return;
    }
    const nodes = items.slice(0, state.shown).map(row);
    if (items.length > state.shown) {
      const more = el("button", "link more", `--More-- (${items.length - state.shown} hidden, press to page)`);
      more.type = "button";
      more.addEventListener("click", () => {
        state.shown += PAGE;
        renderList();
      });
      nodes.push(more);
    }
    list.replaceChildren(...nodes);
  }

  function renderSources(d) {
    const pre = $("sources");
    const lines = d.sources.map((s) => {
      const line = el("span");
      const status = s.ok === true ? ["[  OK  ]", "ok"] : s.ok === false ? ["[FAILED]", "fail"] : ["[ WAIT ]", "wait"];
      line.append(el("span", status[1], status[0]), " ");
      line.append(link(s.label.padEnd(28), s.home));
      line.append(
        ` ${String(s.count).padStart(4)} rows  ${ago(s.fetched_at)}` +
          (s.ok === false ? `  (${s.error || "error"}; showing last good copy)` : "") +
          (s.failed && s.failed.length ? `  (${s.failed.length} down: ${s.failed.join(", ")})` : "") +
          "\n"
      );
      return line;
    });
    pre.replaceChildren(...lines);
  }

  function renderClock() {
    const d = state.data;
    if (!d) return;
    $("sync").textContent = d.generated_at ? `last scrape ${ago(d.generated_at)}` : "first scrape running";
    const left = Math.max(0, Math.floor(d.next_refresh_at - Date.now() / 1000));
    $("countdown").textContent = d.next_refresh_at ? `${pad(Math.floor(left / 60))}:${pad(left % 60)}` : "--:--";
  }

  function render() {
    const d = state.data;
    if (!d.tabs.some((t) => t.key === state.tab)) state.tab = d.tabs[0].key;
    renderStats(d);
    renderTabs(d);
    renderList();
    renderSources(d);
    renderClock();
  }

  // ---- state ------------------------------------------------------------
  function setTab(key) {
    state.tab = key;
    state.shown = PAGE;
    try { history.replaceState(null, "", "#" + key); } catch (_) {}
    if (state.data) { renderTabs(state.data); renderList(); }
  }

  let timer = null;
  async function load() {
    clearTimeout(timer);
    let next = POLL_MS;
    try {
      const resp = await fetch("feed.json", { cache: "no-store" });
      if (!resp.ok) throw new Error(resp.status);
      state.data = await resp.json();
      render();
      const left = state.data.next_refresh_at * 1000 - Date.now();
      // Nothing scraped yet: look again soon. Otherwise wake shortly after the
      // server's next scrape, or at the regular poll, whichever is sooner.
      if (!state.data.generated_at) next = 5000;
      else if (left > 0) next = Math.min(POLL_MS, left + 20000);
    } catch (_) {
      $("sync").textContent = "feed unreachable, retrying";
      next = 30000;
    }
    timer = setTimeout(load, next);
  }

  function setPhosphor(p) {
    document.documentElement.dataset.phosphor = p;
    try { localStorage.setItem("phosphor", p); } catch (_) {}
  }

  // ---- wiring -----------------------------------------------------------
  try {
    const saved = localStorage.getItem("phosphor");
    if (saved === "amber" || saved === "green") document.documentElement.dataset.phosphor = saved;
  } catch (_) {}
  if (location.hash.length > 1) state.tab = location.hash.slice(1);

  const togglePhosphor = () => setPhosphor(document.documentElement.dataset.phosphor === "amber" ? "green" : "amber");
  $("phosphor").addEventListener("click", togglePhosphor);

  const grep = $("grep");
  grep.addEventListener("input", () => {
    state.q = grep.value;
    state.shown = PAGE;
    renderList();
  });

  document.addEventListener("keydown", (e) => {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.target === grep) {
      if (e.key === "Escape") { grep.value = ""; state.q = ""; renderList(); grep.blur(); }
      return;
    }
    if (e.key === "/") { e.preventDefault(); grep.focus(); }
    else if (e.key === "p") togglePhosphor();
    else if (state.data && /^[1-9]$/.test(e.key)) {
      const t = state.data.tabs[Number(e.key) - 1];
      if (t) setTab(t.key);
    }
  });

  setInterval(renderClock, 1000);
  load();
})();
