// Money flow model (V7 hero): victims -> drainers -> payout wallets -> exchanges. Width = USD.
import { mid } from './format'
import type { Case } from './model'
import type { Tier } from './types'
import { chainLong } from './vocab'

export interface FlowNode { id: string; col: number; label: string; v: number; c?: Case; mono?: boolean; x: number; y: number; h: number; so: number; ti: number }
export interface FlowLink { s: string; t: string; v: number; tier: Tier | null }
export interface LaidLink extends FlowLink { S: FlowNode; T: FlowNode; w: number; y0: number; y1: number; d: string }

const PAYOUT_ROLES_SKIP = new Set(['worker', 'submitter', 'funder', 'deployer'])

export function buildFlow(cases: Case[], topN = 7, topW = 6) {
  const live = cases.filter(c => (c.usd || 0) > 0).sort((a, b) => b.usd - a.usd)
  const top = new Set(live.slice(0, topN).map(c => c.key))
  const nodes = new Map<string, FlowNode>()
  const links = new Map<string, FlowLink>()
  let weightedByTxs = false
  const node = (id: string, col: number, label: string, extra: Partial<FlowNode> = {}) => {
    if (!nodes.has(id)) nodes.set(id, { id, col, label, v: 0, x: 0, y: 0, h: 0, so: 0, ti: 0, ...extra })
    return nodes.get(id)!
  }
  const link = (s: string, t: string, v: number, tier: Tier | null) => {
    if (v <= 0) return
    const k = s + '>' + t
    const l = links.get(k) || { s, t, v: 0, tier }
    l.v += v
    if (l.tier !== tier) l.tier = null
    links.set(k, l)
  }
  const walletIn = new Map<string, number>()
  const direct: { entity: string; v: number }[] = []
  live.forEach(c => {
    const cid = top.has(c.key) ? 'c:' + c.key : 'c:other'
    node('v:' + c.chain, 0, 'Victims on ' + chainLong(c.chain))
    if (cid === 'c:other') node(cid, 1, live.length - topN + ' other drainers')
    else node(cid, 1, mid(c.address, 6, 4), { c, mono: true })
    link('v:' + c.chain, cid, c.usd, c.tier)
    const dl = c.vasp_links.filter(v => v.role === 'drainer' && v.usd)
    const straight = dl.reduce((s, v) => s + (v.usd || 0), 0)
    const st = Math.min(straight, c.usd * 0.5)
    if (st > 0) {
      node('p:direct', 2, 'Direct from the drainer')
      link(cid, 'p:direct', st, c.tier)
      dl.forEach(v => direct.push({ entity: v.entity || 'Unknown exchange', v: ((v.usd || 0) * st) / straight }))
    }
    const rest = c.usd - st
    const ps = c.payouts.filter(p => p.wallet && p.wallet !== c.address && !PAYOUT_ROLES_SKIP.has(p.role))
    let weights = ps.map(p => p.share || 0)
    if (weights.every(w => w <= 0) && ps.length) {
      // collectors / customers carry no share: split by the number of payout transactions seen
      weights = ps.map(p => p.txs || 1)
      weightedByTxs = true
    }
    const tot = weights.reduce((s, w) => s + w, 0)
    if (!ps.length || tot <= 0) {
      node('p:none', 2, 'No payout wallet seen')
      link(cid, 'p:none', rest, c.tier)
      return
    }
    ps.forEach((p, i) => {
      const v = (rest * weights[i]) / tot
      if (v <= 0) return
      walletIn.set(p.wallet, (walletIn.get(p.wallet) || 0) + v)
      link(cid, 'w:' + p.wallet, v, c.tier)
    })
  })
  const wallets = [...walletIn.entries()].sort((a, b) => b[1] - a[1])
  const keepW = new Set(wallets.slice(0, topW).map(w => w[0]))
  const remap = (id: string) => (id.startsWith('w:') && !keepW.has(id.slice(2)) ? 'p:other' : id)
  const L2 = new Map<string, FlowLink>()
  links.forEach(l => {
    const t = remap(l.t)
    const k = l.s + '>' + t
    const x = L2.get(k) || { ...l, t, v: 0 }
    x.v += l.v
    if (x.tier !== l.tier) x.tier = null
    L2.set(k, x)
  })
  wallets.forEach(([w]) => {
    if (keepW.has(w)) node('w:' + w, 2, mid(w, 6, 4), { mono: true })
  })
  if (wallets.length > topW) node('p:other', 2, wallets.length - topW + ' other payout wallets')
  const seen = new Set<string>()
  const outW = new Map<string, Map<string, number>>()
  live.forEach(c =>
    c.vasp_links.forEach(v => {
      const id = (v.tx || '') + v.counterparty
      if (v.role !== 'payout' || !v.usd || seen.has(id)) return
      seen.add(id)
      const m = outW.get(v.subject) || new Map<string, number>()
      const e = v.entity || 'Unknown exchange'
      m.set(e, (m.get(e) || 0) + v.usd)
      outW.set(v.subject, m)
    }),
  )
  const L3: { s: string; t: string; v: number }[] = []
  walletIn.forEach((vin, w) => {
    const src = remap('w:' + w)
    const m = outW.get(w) || new Map<string, number>()
    const want = [...m.values()].reduce((s, x) => s + x, 0)
    const k = want > vin ? vin / want : 1
    let used = 0
    m.forEach((x, e) => {
      used += x * k
      L3.push({ s: src, t: 'x:' + e, v: x * k })
    })
    L3.push({ s: src, t: 'x:none', v: vin - used })
  })
  direct.forEach(d => L3.push({ s: 'p:direct', t: 'x:' + d.entity, v: d.v }))
  const none = [...L2.values()].filter(l => l.t === 'p:none').reduce((s, l) => s + l.v, 0)
  if (none) L3.push({ s: 'p:none', t: 'x:none', v: none })
  L3.forEach(l => {
    if (l.v <= 0.5) return
    const k = l.s + '>' + l.t
    const x = L2.get(k) || { s: l.s, t: l.t, v: 0, tier: null }
    x.v += l.v
    L2.set(k, x)
    node(l.t, 3, l.t === 'x:none' ? 'Not seen at an exchange' : l.t.slice(2))
  })
  const all = [...L2.values()].filter(l => l.v > 0.5)
  const vin = new Map<string, number>()
  const vout = new Map<string, number>()
  all.forEach(l => {
    vout.set(l.s, (vout.get(l.s) || 0) + l.v)
    vin.set(l.t, (vin.get(l.t) || 0) + l.v)
  })
  nodes.forEach(n => {
    n.v = Math.max(vin.get(n.id) || 0, vout.get(n.id) || 0)
  })
  return {
    nodes: [...nodes.values()].filter(n => n.v > 0.5),
    links: all,
    total: live.reduce((s, c) => s + c.usd, 0),
    weightedByTxs,
  }
}

export function layoutFlow(model: ReturnType<typeof buildFlow>, W: number, Hh: number) {
  const nodes = model.nodes.map(n => ({ ...n }))
  const cols = [0, 1, 2, 3].map(i => nodes.filter(n => n.col === i))
  const last = (id: string) => (/:(other|none|direct)$/.test(id) ? 1 : 0)
  cols.forEach(c => c.sort((a, b) => last(a.id) - last(b.id) || b.v - a.v))
  const gap = 10, nw = 9, MIN = 18
  const live = cols.filter(c => c.length)
  const k0 = Math.min(...live.map(c => (Hh - gap * (c.length - 1)) / c.reduce((s, n) => s + n.v, 0)))
  const k = Math.max(0, Math.min(...live.map(c =>
    (Hh - gap * (c.length - 1) - c.reduce((s, n) => s + Math.max(0, MIN - n.v * k0), 0)) / c.reduce((s, n) => s + n.v, 0))))
  const xs = [0, 1, 2, 3].map(i => (i * (W - nw)) / 3)
  cols.forEach((c, i) => {
    const h = c.reduce((s, n) => s + Math.max(MIN, n.v * k), 0) + gap * (c.length - 1)
    let y = Math.max(0, (Hh - h) / 2)
    c.forEach(n => {
      n.x = xs[i]
      n.h = Math.max(2, n.v * k)
      const slot = Math.max(MIN, n.h)
      n.y = y + (slot - n.h) / 2
      y += slot + gap
      n.so = 0
      n.ti = 0
    })
  })
  const byId = new Map(nodes.map(n => [n.id, n]))
  const L = model.links
    .map(l => ({ ...l, S: byId.get(l.s)!, T: byId.get(l.t)!, w: Math.max(1, l.v * k), y0: 0, y1: 0, d: '' }))
    .filter(l => l.S && l.T) as LaidLink[]
  L.sort((a, b) => a.T.y - b.T.y).forEach(l => {
    l.y0 = l.S.y + l.S.so + l.w / 2
    l.S.so += l.w
  })
  L.sort((a, b) => a.S.y - b.S.y).forEach(l => {
    l.y1 = l.T.y + l.T.ti + l.w / 2
    l.T.ti += l.w
  })
  L.forEach(l => {
    const x0 = l.S.x + nw, x1 = l.T.x, m = (x0 + x1) / 2
    l.d = `M${x0},${l.y0} C${m},${l.y0} ${m},${l.y1} ${x1},${l.y1}`
  })
  return { nodes, links: L.sort((a, b) => b.w - a.w), nw }
}
