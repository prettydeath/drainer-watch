# Drainer Watch web app

The published dashboard: Vite + React + TypeScript + Tailwind + shadcn/ui, Recharts v3 (shadcn Chart) and anime.js v4.
It fetches `data.json` from its own folder (contract: `../SPEC.md`). Label names come from
`../drainerwatch/template.html` via `scripts/vocab.mjs`, which every npm script runs first.

```bash
npm ci
npm run dev        # put a data.json in public/ (e.g. ../tests/fixtures/sample_data.json)
npm run typecheck
npm test           # Vitest smoke test with ../tests/fixtures/sample_data.json
npm run build      # dist/, copied over site/ by pages.yml (and by `drainerwatch render` when present)
```

Deep link: `#<chain>:<address>` opens that case file. `?theme=dark|light` forces a theme, `?still` turns motion off.
