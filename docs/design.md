# Dashboard design — "Drain seismograph"

Subject: public/analyst monitor of suspected crypto drainer contracts on ETH, BSC and Base.
Audience: cyber-police analysts, exchange compliance, security researchers. Primary job: see what started
draining right now, judge how sure we are (tier + evidence), and see where the money surfaced (exchanges) so
someone can act — freeze or request.

## Tokens

Color (light) — cool forensic-lab paper, one strong color family reserved for confidence tiers:
| name | hex | use |
|---|---|---|
| fog | #EDF0F3 | page background |
| sheet | #F8FAFB | raised surfaces (table, drawer) |
| ink | #18222E | text, rules |
| graphite | #5A6672 | secondary text |
| uv | #2457B8 | interactive: links, focus ring, selected filter |
| t1 crimson | #B0123F | T1 confirmed |
| t2 ochre | #A86A12 | T2 strong |
| t3 slate-violet | #66609E | T3 suspect |

Dark: base #131C27 (deep navy, not black), sheet #1A2532, ink #E3E8EE, graphite #93A0AD, uv #7FA6EE,
t1 #F0567E, t2 #E0A445, t3 #A39DDB. Tier colors are the ONLY saturated colors on the page; chain identity uses
shape/label, not color.

Type (system stacks, no downloads — the file must stay self-contained):
- Display + numerals: `Bahnschrift, "DIN Alternate", "Roboto Condensed", "Arial Narrow", system-ui` — condensed
  engineering face; use its width for big block numbers and the hero sentence. `font-variant-numeric: tabular-nums`.
- Body/UI: `system-ui, -apple-system, "Segoe UI", Roboto, sans-serif`, 15/22.
- Addresses and hashes: `ui-monospace, "Cascadia Mono", Consolas, monospace` — only for on-chain identifiers (they ARE code).
- Scale (1.25): 12 · 13 · 15 · 19 · 24 · 30 · 38. Sentence case everywhere. No all-caps labels, no eyebrows,
  no "A · B · C" meta strings, no "→" on links.

## Layout

```
┌ Drainer Watch ─────────── ETH 26 476 741  BSC 135 241 924  Base 61 167 071 ── updated 2 min ago ─ ◐ ┐
│                                                                                                       │
│  HERO: drain seismograph, last 24 h                                                                  │
│  ETH  ▁▁▂▁▁▁█▁▁▃▁▁▁▁▁▁▂▁▁▁▁▅▁▁▁▁▁▁▁  (one tick per drain, height = log USD, color = tier)              │
│  BSC  ▁▁▁▁▂▁▁▁▁▁▁▁▇▁▁▁▁▁▁▁▂▁▁▁▁▁▁▁                                                                   │
│  Base ▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁                                                                   │
│  "$5,272 left 17 wallets in the last 24 hours. 5 strong and 0 confirmed drainers are active."        │
│                                                                                                       │
├───────────────────────────────────────────────────────┬───────────────────────────────────────────────┤
│ Contracts ledger                                       │ Where the money surfaced (VASP exposure)       │
│ filter sentence: Show [tiers ▾] on [chains ▾] with      │  Binance  ████████  $12,400  3 deposit addrs   │
│ [label ▾] in [cluster ▾]  [search address…]            │  FixedFloat ██       $1,200                     │
│ ▌T1 eth 0xa399…7086  split 71/18/11  deployer…  3  $… │ Operator clusters                               │
│ ▌T2 bsc …                                              │  op_3f2a… 4 contracts · shared 2 wallets         │
│ (left edge bar in tier color = the row's tier)          │                                                 │
├───────────────────────────────────────────────────────┴───────────────────────────────────────────────┤
│ Live drains feed (latest first)          │ Daily: USD drained + new contracts (inline SVG)           │
│ Families · Deployers · Operators (tabs, one table at a time)                                          │
│ Method and limitations (tiers table, detector table, what we cannot see)                              │
└───────────────────────────────────────────────────────────────────────────────────────────────────────┘
Drawer (right, 560 px; full-screen sheet on mobile) = the case file of one contract, sections in reading order:
Verdict (tier, score, why in one sentence) → Evidence → Money split → Deployer → Where funds surfaced →
Cluster (other members, clickable) → Same contract on other chains → Raw facts.
```
Left-aligned everything; numbers right-aligned in tables. Sections are separated by whitespace and one ink
rule, not boxed into identical cards. Radius: 2 px on inputs/buttons, 0 on table rows, 10 px only on the drawer.

## Principles
1. The seismograph is the one memorable thing. Everything else is quiet ink on fog.
2. Color means confidence. If something is crimson, it is T1 — nothing decorative uses tier colors.
3. Every claim links to its proof (tx/explorer). Full identifiers on hover/copy; middle-ellipsis in tables.
4. Plain sentences over labels: the hero and the filter bar read as sentences.
5. One motion moment: seismograph ticks draw in once on load (respect prefers-reduced-motion). Drawer slides
   in because the user opened it. Nothing else animates.
6. Quality floor: 375 px works (seismograph lanes scroll horizontally inside their own box), visible
   focus ring in uv, keyboard: Esc closes drawer, / focuses search.
