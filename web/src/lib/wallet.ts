// Wallet case file: everything data.json knows about one payout / recipient / holder wallet.
// Uses data.json `wallets` (aggregated by render.py from the full drains table) when present; otherwise falls back to
// payouts in contracts[], the capped drains[] list, vasp_links and freezable rows.
import { freezeRows, type FreezeRow } from './analytics'
import { toMs } from './format'
import type { Case, Model } from './model'
import type { Tier, WalletDrainer, WalletInflow, WalletOutflow } from './types'
import { TIER_RANK } from './vocab'

export interface LinkedDrainer extends WalletDrainer { c: Case | null }
export interface WalletFile {
  chain: string
  address: string
  key: string
  /** true when data.json carries the backend aggregate for this wallet */
  full: boolean
  roles: string[]
  drainers: LinkedDrainer[]
  bestTier: Tier | null
  inflows: (WalletInflow & { t: number })[]
  outflows: WalletOutflow[]
  firstIn: number
  lastIn: number
  totalIn: number
  nIn: number
  holdings: FreezeRow[]
  clusters: { cluster: string; members: number; shared: boolean }[]
  known: boolean
}

export const walletKey = (chain: string, address: string) => chain + ':' + address
const lc = (s: string | null | undefined) => (s || '').toLowerCase()

export function walletFile(model: Model, chain: string, address: string): WalletFile {
  const same = (a: string | null | undefined) => lc(a) === lc(address)
  const caseOf = (d: string) => model.byKey.get(chain + ':' + d) || model.cases.find(x => x.chain === chain && same2(x.address, d)) || null
  const same2 = (a: string, b: string) => lc(a) === lc(b)
  const agg = model.data.wallets
    ? model.data.wallets[walletKey(chain, address)] ||
      Object.entries(model.data.wallets).find(([k]) => lc(k) === lc(walletKey(chain, address)))?.[1]
    : undefined
  // the address as the data spells it
  const spelled = model.cases.flatMap(c => (c.chain === chain ? c.payouts.map(p => p.wallet) : [])).find(same) ||
    (model.freezable || []).find(f => f.chain === chain && same(f.address))?.address || address

  const roles = new Set<string>(agg?.roles || [])
  const linked = new Map<string, LinkedDrainer>()
  ;(agg?.drainers || []).forEach(d => linked.set(lc(d.drainer), { ...d, c: caseOf(d.drainer) }))
  model.cases.forEach(c => {
    if (c.chain !== chain) return
    c.payouts.forEach(p => {
      if (!same(p.wallet)) return
      roles.add(p.role)
      if (!linked.has(lc(c.address)))
        linked.set(lc(c.address), { drainer: c.address, tier: c.tier, role: p.role, share: p.share, usd: 0, txs: 0, first: null, last: null, c })
    })
  })
  const holdings = freezeRows(model).filter(r => r.f.chain === chain && same(r.f.address))
  holdings.forEach(r => {
    roles.add(r.f.role)
    if (r.f.drainer && !linked.has(lc(r.f.drainer)))
      linked.set(lc(r.f.drainer), { drainer: r.f.drainer, tier: r.c?.tier || r.f.drainer_tier, role: r.f.role, share: null, usd: 0, txs: 0, first: null, last: null, c: r.c })
  })

  // inflows: backend list, else the published drains with this recipient
  let inflows: WalletFile['inflows']
  if (agg) inflows = agg.inflows.map(i => ({ ...i, t: toMs(i.ts) }))
  else {
    inflows = model.drains.filter(d => d.chain === chain && same(d.recipient) && !same(d.drainer))
      .map(d => ({ tx: d.tx, ts: d.ts, victim: d.victim, drainer: d.drainer, token: d.token, symbol: d.symbol, amount: d.amount, usd: d.usd, t: d.t }))
    inflows.forEach(i => {
      const l = linked.get(lc(i.drainer)) || { drainer: i.drainer, tier: caseOf(i.drainer)?.tier || null, role: null, share: null, usd: 0, txs: 0, first: null, last: null, c: caseOf(i.drainer) }
      l.usd += i.usd || 0
      l.txs += 1
      l.first = !l.first || toMs(i.ts) < toMs(l.first) ? i.ts : l.first
      l.last = !l.last || toMs(i.ts) > toMs(l.last) ? i.ts : l.last
      linked.set(lc(i.drainer), l)
    })
  }
  inflows.sort((a, b) => b.t - a.t)

  // outflows: backend list, else exchange links of any case with this wallet as subject
  const outflows: WalletOutflow[] = agg ? agg.outflows_known : []
  if (!agg) {
    const seen = new Set<string>()
    model.cases.forEach(c => c.chain === chain && c.vasp_links.forEach(v => {
      if (!same(v.subject) || seen.has(v.tx + v.counterparty)) return
      seen.add(v.tx + v.counterparty)
      outflows.push({ counterparty: v.counterparty, kind: v.kind, entity: v.entity, category: v.category, tx: v.tx, tx_in: v.tx_in, ts: v.ts, amount: v.amount, symbol: v.symbol, usd: v.usd, confidence: v.confidence })
    }))
  }

  const drainers = [...linked.values()].sort((a, b) => b.usd - a.usd || TIER_RANK[a.tier || 'T3'] - TIER_RANK[b.tier || 'T3'])
  const bestTier = drainers.map(d => d.c?.tier || d.tier).filter((x): x is Tier => !!x).sort((a, b) => TIER_RANK[a] - TIER_RANK[b])[0] || null
  const ts = inflows.map(i => i.t).filter(Number.isFinite)
  const clusters = model.data.clusters.filter(cl => cl.chain === chain &&
    (cl.shared_wallets.some(same) || drainers.some(d => cl.members.some(m => same2(m, d.drainer)))))
    .map(cl => ({ cluster: cl.cluster, members: cl.members.length, shared: cl.shared_wallets.some(same) }))
  const firstIn = agg?.first_in ? toMs(agg.first_in) : ts.length ? Math.min(...ts) : NaN
  const lastIn = agg?.last_in ? toMs(agg.last_in) : ts.length ? Math.max(...ts) : NaN
  return {
    chain, address: spelled, key: walletKey(chain, spelled), full: !!agg,
    roles: [...roles].filter(Boolean).sort(),
    drainers, bestTier, inflows, outflows,
    firstIn, lastIn,
    totalIn: agg ? agg.total_in_usd : inflows.reduce((s, i) => s + (i.usd || 0), 0),
    nIn: agg ? agg.n_in : inflows.length,
    holdings, clusters,
    known: !!agg || drainers.length > 0 || holdings.length > 0 || inflows.length > 0 || outflows.length > 0,
  }
}
