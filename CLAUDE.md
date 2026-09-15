# CLAUDE.md — context for crild/dashboard

Written as a handoff from a planning chat. Safe to commit: the repo is **public**, so personal financial figures, account details and secrets are deliberately left out. Keep them in Worker secrets / KV config, never in git.

## 1. What this is

- Personal house dashboard for Charles (Oslo). Target surface: a wall-mounted tablet in the hallway, plus phone/desktop.
- **Frontend:** `index.html` — one file, ~6 300 lines, HTML + CSS + JS. Served by GitHub Pages as a project site at `crild.github.io/dashboard/` (branch `main`, root). No build step, no `.github/` workflows.
- **Backend:** Cloudflare Worker at `yahoopull.charles-rutherford93.workers.dev`, source in `cloudflare-worker-deploy.js` (the live one, ~390 lines). `cloudflare-worker.js` is the old v1 plain proxy (64 lines) — legacy, candidate for deletion.
- **Storage:** Workers KV — OAuth tokens (Netatmo, Hue) and shared config blobs.
- History: 47 commits, all on 13–14 March 2026. Single-file architecture is intentional (trivial Pages deploy); revisit splitting JS only if the agent work makes `index.html` unmanageable.
- Unrelated repo `crild/crild.github.io` (2019 Jekyll test site) owns the domain root. Zero code coupling. Nice-to-have: replace its `index.md` with a redirect to `/dashboard/`.

## 2. Current widgets and data paths

| Widget | Source | Path |
|---|---|---|
| weather | Open-Meteo | direct from browser |
| stocks | Yahoo Finance | via Worker `/proxy` |
| news | RSS (NRK, BBC, Verge, Ars, Google News, HN, E24, VG, TechCrunch) | via Worker |
| sensors | Netatmo (CO₂ etc.) | Worker OAuth, `/netatmo/*` |
| hue | Hue Remote API | Worker OAuth, `/hue/*` |
| power | hvakosterstrommen.no | direct |
| transit | Entur GraphQL, nearest-stop + walk time | direct |
| waste | Oslo kommune / Norkart | Worker `/waste/calendar` |
| mobility | OSM tiles + Valhalla/OSRM routing | direct |

Worker routes: `/proxy` (host allowlist), `/auth/netatmo`, `/auth/hue`, `/callback/*`, `/netatmo/*`, `/hue/*`, `/config/save`, `/config/load` (8-char share code, KV), `/waste/calendar`.

Secrets (Worker): `NETATMO_CLIENT_ID/SECRET`, `HUE_CLIENT_ID/SECRET`, `DASHBOARD_TOKEN`. Client keeps the dashboard token in `localStorage['dashboard-token']`.

Code anchors: `loadConfig()` ~L1841, `getDashboardToken()` ~L1880, `WORKER_BASE` ~L5726, `saveConfigToCloud()` ~L5743, `exportConfig()` ~L5833 in `index.html`; `checkDashboardToken()` L18 and `generateCode()` in `cloudflare-worker-deploy.js`.

## 3. Known issues (fix before adding agent routes)

1. `checkDashboardToken()` **fails open** when `DASHBOARD_TOKEN` is unset. Verify the secret is set in Cloudflare; make any new `/brief/*` and `/index/*` routes fail closed.
2. Token is also accepted as `?token=` query param → ends up in logs. Prefer header-only (`X-Dashboard-Token`).
3. Two Worker files; delete v1 once confirmed unused.
4. Shared config via `/config/save` excludes the token — keep it that way when adding new config fields.

## 4. Roadmap (agreed order)

### 4.1 "Vibes" indexes widget
- One `indexes` widget rendering a grid of small tiles, driven by config entries: `{name, emoji, url, extractor, scale, refresh}`. Adding an index = data, not code.
- Worker route `/index/:name`: fetch → parse → cache in KV with per-source TTL (hourly for sentiment gauges, daily for slow series, yearly for static ones). Dashboard only ever reads clean JSON.
- Fail soft: grey tile with last known value when a source breaks.
- Candidate sources (Charles picks 6–8):
  - Same genre: SALSA Index (server-rendered HTML — regex on `SALSA INDEX:` and `TACO PROBABILITY:`), AI Bubble Monitor (client-rendered; find its JSON endpoint via DevTools → Network), CNN Fear & Greed (unofficial JSON at `production.dataviz.cnn.io/index/fearandgreed/graphdata`, needs browser UA), Crypto Fear & Greed (`api.alternative.me/fng/`), Buffett Indicator, Shiller CAPE, VIX/MOVE via existing Yahoo pipe, Mag 7 share of S&P, "Nvidia vs Oljefondet", Polymarket odds (Gamma API), Metaculus AGI date, FRED series (`SAHMREALTIME`, `T10Y2Y`, `STLFSI4`, misery index from `UNRATE` + CPI).
  - Planet: NOAA CO₂ ppm (pairs with the indoor CO₂ card), Climate Reanalyzer temperature anomaly, US debt (Treasury Fiscal Data API), Doomsday Clock (static, yearly), people in space (`api.open-notify.org/astros.json`).
  - Norwegian: Oljefondet live value (NBIM JSON behind homepage counter) and "your share", EUR/NOK + styringsrente (Norges Bank open API `data.norges-bank.no`), boligprisindeks (Eiendom Norge / SSB JSON-stat), Oslo air quality (`api.nilu.no`), seasonal slot rotating pollen / badetemperatur / skiføre.
  - Meme tier (flaky, scrape): Pentagon Pizza Index, Big Mac Index (`TheEconomist/big-mac-data` on GitHub), Baltic Dry Index, Bitcoin days-since-ATH.
- Prefer official JSON where it exists; scraping only for meme tier.

### 4.2 Claude agent briefs
- Runner: **Cloudflare Cron Triggers in the existing Worker** (decided over Pi). 06:00 daily; Monday 06:00 weekly; Sunday evening weekly.
- Pipeline: deterministic collectors (Yahoo, Norges Bank, FRED, RSS, property index, holdings config) → one Claude API call with system prompt + structured data + the API `web_search` tool → JSON against a fixed schema `{headline, bullets[], relevance_to_me[], sources[]}` → KV `brief:daily:YYYY-MM-DD`, `brief:weekly:YYYY-Www` (retain history) → dashboard card with Daily/Weekly tabs, timestamp, grey "stale" badge if a run failed.
- `ANTHROPIC_API_KEY` as Worker secret. `/brief/*` behind the dashboard token, fail closed.
- Model routing: small model for the daily, stronger model for weekly runs. Cost order of magnitude: a few kroner per run; check docs.claude.com/pricing.
- Three agents, kept separate:
  1. **Net worth & 2030 tracker (weekly).** All arithmetic in code, not the model: properties valued by index scaling from last known value, listed funds from provider NAV pages, unlisted holdings and cash as manual inputs with date stamps, loans/receivables from amortization schedules + Norges Bank FX. Output: total and owner's share, 4-week/YTD change decomposed by driver (property index, equities, savings inflow, debt paydown, FX), progress meter vs the ~2030 property upgrade target. Model writes narrative and anomaly flags only. **Privacy mode:** default display as index (base 100) and % changes; tap/PIN to reveal absolute values (hallway screen). One earmarked cash pot must render as *restricted*.
  2. **Market moves (daily).** Overnight moves — S&P, Nasdaq, OSEBX, Brent, EUR/NOK, USD/NOK, US 10Y, NIBOR — plus watchlist and the vibes indexes. 3–5 bullets with sources, one line on personal relevance (rates → mortgage, NOK → a CAD receivable).
  3. **Investment hypotheses (weekly).** Hypothesis *generator and tracker*, not tips: each entry has thesis, confirm/refute conditions, horizon; scored on later runs. Norway-aware (ASK wrapper, skjermingsfradrag, no tax event on rotation inside ASK). Always framed as research, not advice.
- Manual inputs (~3/month) entered via a small config UI in the dashboard, stored in KV via the existing config mechanism — never in the repo.

### 4.3 Housekeeping
- Kiosk mode for the wall tablet (hide chrome/drag handles, auto-refresh, wake lock).
- Root redirect from `crild.github.io` → `/dashboard/`.
- Delete legacy Worker file.

### 4.4 Home Assistant integration — deferred
- Decision: **no hub for now.** Devices run on their own schedules (ELKO thermostats' built-in program + external-control input for central setback; Plejd app timers; Hue bridge; Tibber smart charging for the EV charger).
- Revisit when ≥2 triggers bite (remote heating override, sensors in the rental flat, per-room heating cost data, app fatigue). Then: Home Assistant Green + ZBT-1 first; Pi 5 8 GB shopping list exists if more headroom is needed. Dashboard would then read HA over WebSocket on LAN — the wall display is a separate tablet, never the hub itself.

## 5. Working with Charles

- Engineer, ex-McKinsey. Top-down: lead with the answer, then bullets/dot-dash. Tight prose. Explicit assumptions, real numbers, scenario tables over qualitative hand-waving.
- Corrects assumptions actively — integrate corrections immediately.
- English for tech/software; Norwegian for tax, legal, construction. Keep Norwegian technical terms in the original.
- When editing UI or drawings: change only the element asked for.
- DIY orientation; prefers owning the stack over off-the-shelf integrations.

## 6. Open questions

- Which 6–8 indexes for v1 of the widget.
- Net worth: owner's share only, or household with a co-owner split.
- Which EV charger model was installed (affects any later energy work).
- Spot price vs Norgespris tariff (decides whether spot-shifting logic is worth building).

## 7. Local development and agent hygiene

`node dev.mjs` serves `index.html` on 127.0.0.1:8765 and runs `wrangler dev` on
127.0.0.1:8787. Both bind loopback deliberately, so neither needs a Windows
Firewall exception — if a firewall prompt appears for Node, something has bound
the wrong address. Cancel it and find out what.

Rules for any throwaway server started while testing:

- **Bind loopback explicitly**: `listen(port, '127.0.0.1')`. Bare `listen(port)`
  binds every interface, which raises the firewall prompt and, on a network you
  do not control, offers the served directory to anyone on it.
- **Serve a temp directory, not the repo**, unless you are running `dev.mjs`
  itself. `dev.mjs` serves the repo root on purpose — that is how it serves
  `index.html` — and is safe because it binds loopback. An ad-hoc server that
  gets the host argument wrong and serves this directory hands out
  `spareplan-config.json`, which is gitignored precisely because it must not
  leave the machine. Loopback is what makes either one safe; the directory is
  what decides how bad the mistake is.
- **Stop it when done.** A background server outlives the task that started it.

`wrangler dev` watches `cloudflare-worker-deploy.js` and restarts on every write,
so it should not be left running through a long editing session.
