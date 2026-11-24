// Analytics tab: ranking and aggregation over the published data.json (pure functions, unit-tested).
// Per-drainer totals (usd, victims, drains, first_seen, last_seen) come from contracts[] and cover the full history;
// drain-level views (unpriced counts, timeline dots, per-chain series, window recipients) use drains[], which render.py
// caps at the latest MAX_DRAINS rows.
import { DAY, H } from './format'
import type { Case, DrainRow, Model } from './model'
import type { Payout, Tier } from './types'
import { TIER_RANK } from './vocab'

export type WindowKey = '24h' | '7d' | '30d' | 'all'
export const WINDOWS: { key: WindowKey; label: string; ms: number; phrase: string }[] = [
  { key: '24h', label: '24 hours', ms: DAY, phrase: 'in the last 24 hours' },
  { key: '7d', label: '7 days', ms: 7 * DAY, phrase: 'in the last 7 days' },
  { key: '30d', label: '30 days', ms: 30 * DAY, phrase: 'in the last 30 days' },
  { key: 'all', label: 'All time', ms: Infinity, phrase: 'at any time' },
]
export const windowOf = (k: WindowKey) => WINDOWS.find(w => w.key === k) || WINDOWS[1]

export interface Filter { tiers: Tier[]; chain: string; window: WindowKey }
export const DEFAULT_FILTER: Filter = { tiers: ['T1', 'T2'], chain: 'all', window: '7d' }

export interface Exposure { entity: string; usd: number; links: number }
export interface DrainerRow {
  c: Case
  rank: number
  usd: number
  unpriced: number
  victims: number
  drains: number
  start: number
  last: number
  duration: number
  recipients: Payout[]
  exposure: Exposure[]
  exposureUsd: number
  cluster: string | null
}

const ts = (s: string | null | undefined) => {
  const t = Date.parse(s || '')
  return Number.isFinite(t) ? t : NaN
}

export function exposureOf(c: Case): Exposure[] {
  const m = new Map<string, Exposure>()
  const seen = new Set<string>()
  c.vasp_links.forEach(v => {
    if (v.role === 'deployer') return
    const id = (v.tx || '') + v.counterparty
    if (seen.has(id)) return
    seen.add(id)
    const k = v.entity || 'Unnamed exchange'
    const e = m.get(k) || { entity: k, usd: 0, links: 0 }
    e.usd += v.usd || 0
    e.links++
    m.set(k, e)
  })
  return [...m.values()].sort((a, b) => b.usd - a.usd || b.links - a.links)
}

/** Drainers matching the filter, ranked by USD taken (then drains, then most recent activity). */
export function drainerRows(model: Model, f: Filter): DrainerRow[] {
  const w = windowOf(f.window)
  const since = model.now - w.ms
  const rows = model.cases
    .filter(c => f.tiers.includes(c.tier) && (f.chain === 'all' || c.chain === f.chain))
    .filter(c => w.ms === Infinity || ts(c.last_seen) >= since)
    .map(c => {
      // campaign start: first evidence or first drain, whichever is earlier; last activity likewise
      const dts = c.drainList.map(d => d.t).filter(Number.isFinite)
      const fs = ts(c.first_seen), ls = ts(c.last_seen)
      const start = dts.length ? Math.min(...dts, Number.isFinite(fs) ? fs : Infinity) : fs
      const last = dts.length ? Math.max(...dts, Number.isFinite(ls) ? ls : -Infinity) : ls
      const exposure = exposureOf(c)
      return {
        c,
        rank: 0,
        usd: c.usd || 0,
        unpriced: c.drainList.filter(d => d.usd == null).length,
        victims: c.victims || 0,
        drains: c.drains || 0,
        start,
        last,
        duration: Number.isFinite(start) && Number.isFinite(last) ? Math.max(0, last - start) : NaN,
        recipients: c.payouts.slice().sort((a, b) => (b.share || 0) - (a.share || 0) || (b.txs || 0) - (a.txs || 0)),
        exposure,
        exposureUsd: exposure.reduce((s, e) => s + e.usd, 0),
        cluster: c.cluster || null,
      }
    })
  rows.sort((a, b) => b.usd - a.usd || b.drains - a.drains || (b.last || 0) - (a.last || 0) || TIER_RANK[a.c.tier] - TIER_RANK[b.c.tier])
  rows.forEach((r, i) => { r.rank = i + 1 })
  return rows
}

export type SortKey = 'rank' | 'usd' | 'victims' | 'drains' | 'start' | 'last' | 'duration' | 'recipients' | 'exposure'
const sortVal = (r: DrainerRow, k: SortKey): number => {
  switch (k) {
    case 'rank': return r.rank
    case 'usd': return r.usd
    case 'victims': return r.victims
    case 'drains': return r.drains
    case 'start': return r.start
    case 'last': return r.last
    case 'duration': return r.duration
    case 'recipients': return r.recipients.length
    case 'exposure': return r.exposureUsd
  }
}
/** Stable sort; missing values (NaN) always go last. */
export function sortRows(rows: DrainerRow[], key: SortKey, dir: 'asc' | 'desc'): DrainerRow[] {
  const s = dir === 'asc' ? 1 : -1
  return rows.slice().sort((a, b) => {
    const x = sortVal(a, key), y = sortVal(b, key)
    const xn = !Number.isFinite(x), yn = !Number.isFinite(y)
    if (xn || yn) return xn && yn ? a.rank - b.rank : xn ? 1 : -1
    return (x - y) * s || a.rank - b.rank
  })
}

export interface Summary { drainers: number; usd: number; victims: number; top3: number; top3Share: number; priced: number; unpriced: number }
export function summarize(rows: DrainerRow[]): Summary {
  const usd = rows.reduce((s, r) => s + r.usd, 0)
  const top3 = rows.slice().sort((a, b) => b.usd - a.usd).slice(0, 3).reduce((s, r) => s + r.usd, 0)
  return {
    drainers: rows.length,
    usd,
    victims: rows.reduce((s, r) => s + r.victims, 0),
    top3,
    top3Share: usd > 0 ? top3 / usd : 0,
    priced: rows.filter(r => r.usd > 0).length,
    unpriced: rows.reduce((s, r) => s + r.unpriced, 0),
  }
}

/** What the drains[] list covers: it is capped, so drain-level views only reach back to `from`. */
export function drainWindow(model: Model) {
  const t = model.drains.map(d => d.t).filter(Number.isFinite)
  return { n: model.drains.length, from: t.length ? Math.min(...t) : NaN, to: t.length ? Math.max(...t) : NaN }
}

export interface Recipient {
  chain: string
  wallet: string
  roles: string[]
  drainers: Case[]
  usd: number
  /** 'full': usd from operators[] (every drain to this wallet); 'window': summed from the published drains only */
  basis: 'full' | 'window' | 'none'
}
/** Payout wallets and drain recipients of the given drainers, aggregated across drainers. */
export function recipients(model: Model, rows: DrainerRow[]): Recipient[] {
  const ops = new Map(model.data.operators.map(o => [o.chain + ':' + o.wallet.toLowerCase(), o]))
  const m = new Map<string, Recipient & { win: number }>()
  const get = (chain: string, wallet: string) => {
    const k = chain + ':' + wallet.toLowerCase()
    let r = m.get(k)
    if (!r) { r = { chain, wallet, roles: [], drainers: [], usd: 0, basis: 'none', win: 0 }; m.set(k, r) }
    return r
  }
  rows.forEach(({ c }) => {
    c.payouts.forEach(p => {
      const r = get(c.chain, p.wallet)
      if (!r.roles.includes(p.role)) r.roles.push(p.role)
      if (!r.drainers.includes(c)) r.drainers.push(c)
    })
    c.drainList.forEach(d => {
      if (!d.recipient || d.recipient.toLowerCase() === c.address.toLowerCase()) return
      const r = get(c.chain, d.recipient)
      if (!r.drainers.includes(c)) r.drainers.push(c)
      r.win += d.usd || 0
    })
  })
  const out: Recipient[] = [...m.entries()].map(([k, r]) => {
    const o = ops.get(k)
    const full = o ? o.usd || 0 : 0
    const usd = Math.max(full, r.win)
    return { chain: r.chain, wallet: r.wallet, roles: r.roles.length ? r.roles : ['recipient'], drainers: r.drainers, usd,
      basis: usd <= 0 ? 'none' : full >= r.win ? 'full' : 'window' }
  })
  return out.sort((a, b) => b.usd - a.usd || b.drainers.length - a.drainers.length || a.wallet.localeCompare(b.wallet))
}

export interface Bucketed { rows: Record<string, number>[]; chains: string[]; bucket: '10 minutes' | 'hour' | 'day'; total: number }
/** USD taken per time bucket and chain, from the published drains of the given drainers. */
export function perChainSeries(rows: DrainerRow[]): Bucketed {
  const ds: DrainRow[] = rows.flatMap(r => r.c.drainList).filter(d => Number.isFinite(d.t))
  if (!ds.length) return { rows: [], chains: [], bucket: 'day', total: 0 }
  const lo = Math.min(...ds.map(d => d.t)), hi = Math.max(...ds.map(d => d.t))
  const size = hi - lo <= 6 * H ? H / 6 : hi - lo <= 3 * DAY ? H : DAY
  const bucket = size === H / 6 ? '10 minutes' : size === H ? 'hour' : 'day'
  const chains = [...new Set(ds.map(d => d.chain))].sort()
  const first = Math.floor(lo / size) * size, last = Math.floor(hi / size) * size
  const m = new Map<number, Record<string, number>>()
  for (let t = first; t <= last; t += size) m.set(t, Object.fromEntries([['t', t], ...chains.map(c => [c, 0])]))
  let total = 0
  ds.forEach(d => {
    const b = m.get(Math.floor(d.t / size) * size)!
    b[d.chain] += d.usd || 0
    total += d.usd || 0
  })
  const out = [...m.values()].map(b => { chains.forEach(c => { b[c] = Math.round(b[c] * 100) / 100 }); return b })
  if (out.length === 1) out.unshift({ ...Object.fromEntries(chains.map(c => [c, 0])), t: first - size })
  return { rows: out, chains, bucket, total }
}

const csvCell = (v: unknown) => {
  const s = v == null ? '' : String(v)
  return /[",\n\r]/.test(s) || /^[=+\-@]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s
}
const iso = (t: number) => (Number.isFinite(t) ? new Date(t).toISOString().replace('.000Z', 'Z') : '')
export const CSV_HEAD = ['rank', 'tier', 'chain', 'address', 'name', 'family', 'family_name_source', 'contract_name', 'usd', 'unpriced_in_published_drains',
  'victims', 'drains', 'campaign_start', 'last_activity', 'duration_hours', 'recipients', 'exchanges', 'cluster']
export function toCSV(rows: DrainerRow[]): string {
  const lines = rows.map(r => [
    r.rank, r.c.tier, r.c.chain, r.c.address, r.c.title, r.c.family || '', r.c.famSource || '', r.c.contract_name || '', Math.round(r.usd * 100) / 100, r.unpriced,
    r.victims, r.drains, iso(r.start), iso(r.last), Number.isFinite(r.duration) ? Math.round((r.duration / H) * 10) / 10 : '',
    r.recipients.map(p => p.wallet + ' ' + p.role + (p.share ? ' ' + Math.round(p.share * 100) + '%' : '')).join('; '),
    r.exposure.map(e => e.entity + ' ' + Math.round(e.usd)).join('; '), r.cluster || '',
  ].map(csvCell).join(','))
  return [CSV_HEAD.join(','), ...lines].join('\r\n') + '\r\n'
}

/** Human duration: "3 h", "2 d 4 h", "41 d". */
export function fmtDuration(ms: number) {
  if (!Number.isFinite(ms)) return 'unknown'
  if (ms < 60e3) return 'under 1 min'
  if (ms < H) return Math.round(ms / 60e3) + ' min'
  if (ms < DAY) return Math.round(ms / H) + ' h'
  const d = Math.floor(ms / DAY), h = Math.round((ms - d * DAY) / H)
  return d >= 10 || !h ? d + ' d' : d + ' d ' + h + ' h'
}

/* ---- tab routing ---- */
export type Tab = 'overview' | 'analytics'
export type Route = { tab: Tab | null; caseRef: { chain: string; address: string } | null }
/** '#analytics' / '#overview' pick a tab; '#chain:address' opens a case without changing the tab;
 *  an empty hash or a section anchor (#flow, #files...) belongs to the overview. */
export function parseRoute(hash: string): Route {
  const h = decodeURIComponent(hash.replace(/^#/, ''))
  if (h === 'analytics' || h === 'overview') return { tab: h, caseRef: null }
  const m = /^([a-z0-9]+):(\S+)$/i.exec(h)
  if (m) return { tab: null, caseRef: { chain: m[1].toLowerCase(), address: m[2] } }
  return { tab: 'overview', caseRef: null }
}

/* ---- freezable stablecoins ---- */
export interface FreezeSummary { usd: number; frozen: number; byIssuer: [string, number][]; symbols: string[]; n: number; checked: number }
/** Sentence numbers for "Freezable now". Issuer totals come from freezable_total when the backend sends it. */
export function freezeSummary(model: Model): FreezeSummary | null {
  const rows = model.freezable
  if (!rows) return null
  const open = rows.filter(f => !f.already_frozen)
  const by = new Map<string, number>()
  const tot = model.data.freezable_total
  if (tot && Object.keys(tot).length) Object.entries(tot).forEach(([k, v]) => by.set(k, Number(v) || 0))
  else open.forEach(f => { const k = f.issuer || 'Unknown issuer'; by.set(k, (by.get(k) || 0) + (f.usd || 0)) })
  const byIssuer = [...by.entries()].filter(e => e[1] > 0).sort((a, b) => b[1] - a[1])
  const checked = rows.map(f => ts(f.checked_at)).filter(Number.isFinite)
  return {
    usd: byIssuer.reduce((s, e) => s + e[1], 0),
    frozen: rows.filter(f => f.already_frozen).reduce((s, f) => s + (f.usd || 0), 0),
    byIssuer,
    symbols: [...new Set(open.map(f => f.symbol).filter((x): x is string => !!x))].sort(),
    n: open.length,
    checked: checked.length ? Math.max(...checked) : NaN,
  }
}
/** Short per-row hint (table cell). */
export function freezeHintShort(issuer: string | null | undefined, symbol?: string | null) {
  const s = (issuer || '') + ' ' + (symbol || '')
  return /tether|usdt/i.test(s) ? 'Tether: law-enforcement request' : /circle|usdc|eurc/i.test(s) ? 'Circle: law-enforcement request' : 'Issuer compliance, via law enforcement'
}
/** Neutral one-line hint on how a freeze is usually requested; no links we cannot verify. */
export function freezeHint(issuer: string | null | undefined, symbol?: string | null) {
  const s = (issuer || '') + ' ' + (symbol || '')
  if (/tether|usdt/i.test(s)) return 'Tether acts on requests from law enforcement, sent through its law-enforcement request channel.'
  if (/circle|usdc|eurc/i.test(s)) return 'Circle reviews freeze requests for USDC that come from law enforcement.'
  return 'The issuer’s compliance team decides on freezes; requests usually come from law enforcement.'
}
