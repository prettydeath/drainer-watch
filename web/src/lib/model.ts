import { DAY } from './format'
import type { ChainInfo, Contract, DataJson, Drain, Freezable, Tier } from './types'
import { EOA_LABELS, METHOD_AXES, TIER_RANK, chainShort, famBlurb, famLabel, famName } from './vocab'

export interface DrainRow extends Drain { t: number; tier: Tier | null; key: string }
export interface Case extends Contract {
  key: string
  drainList: DrainRow[]
  isWallet: boolean | null
  title: string
  caseNo: string
  /** primary family label (family_name, else the vocab name of the hash); null when no family */
  famLabel: string | null
  famSource: string | null
}
export interface Family {
  key: string
  name: string
  source: string | null
  blurb: string
  contracts: Case[]
  usd: number
  d7: number
  profile: { axis: string; value: number }[]
  axes: number
}
export interface SearchHit { key: string; value: string; role: string }
export interface Model {
  data: DataJson
  now: number
  cases: Case[]
  byKey: Map<string, Case>
  drains: DrainRow[]
  chains: [string, ChainInfo][]
  fams: Family[]
  index: { v: string; value: string; role: string; key: string }[]
  headline: { usd: number; victims: number; drainers: number; surfaced: number; suspects: number }
  /** null when data.json has no `freezable` field (not computed yet) */
  freezable: Freezable[] | null
  /** per case key: freezable rows linked to that drainer and the USD not yet frozen */
  freezeByCase: Map<string, { usd: number; rows: Freezable[] }>
}

const DEFAULT_EXPLORER: Record<string, string> = {
  eth: 'https://etherscan.io', bsc: 'https://bscscan.com', base: 'https://basescan.org', tron: 'https://tronscan.org/#',
}
let CHAINS: Record<string, ChainInfo> = {}
const explorer = (ch: string) => (CHAINS[ch]?.explorer || DEFAULT_EXPLORER[ch] || '').replace(/\/$/, '')
const isTron = (ch: string) => ch === 'tron' || /tronscan/.test(explorer(ch))
export const txUrl = (ch: string, tx: string) =>
  explorer(ch) + '/' + (CHAINS[ch]?.tx_path || (isTron(ch) ? 'transaction' : 'tx')) + '/' + tx
export const addrUrl = (ch: string, a: string) => explorer(ch) + '/address/' + a
export const hasExplorer = (ch: string) => !!explorer(ch)

export const caseKey = (chain: string, address: string) => chain + ':' + address
const norm = (s: string) => s.toLowerCase()

function walletKind(c: Contract): boolean | null {
  if (c.is_contract === false || c.code_size === 0) return true
  if (c.is_contract === true || (c.code_size || 0) > 0) return false
  return c.labels.some(l => EOA_LABELS.has(l)) ? true : null
}

export function caseTitle(c: Contract, isWallet: boolean | null) {
  if (c.family) return famLabel(c.family, c.family_name, c.family_name_source)
  if (c.contract_name) return c.contract_name
  return isWallet ? 'Drainer wallet' : 'Unattributed drainer'
}

// vocab families are kit fingerprints; f_<hash> without a name is a bare code-hash group
const V_SRC = (hash: string) => (/^f_/.test(hash) ? 'hash' : 'kit')

export function methodProfile(cs: Case[]) {
  const sig = cs.map(c => new Set([...c.labels, ...c.evidence.map(e => e.type)]))
  return METHOD_AXES.map(([axis, keys]) => ({
    axis,
    value: Math.round((100 * sig.filter(s => keys.some(k => s.has(k))).length) / Math.max(1, cs.length)),
  }))
}

export function buildModel(raw: DataJson): Model {
  const data: DataJson = {
    generated_at: raw.generated_at || '',
    chains: raw.chains || {},
    totals: raw.totals || { tiers: { T1: 0, T2: 0, T3: 0 }, victims_24h: 0, usd_24h: 0, usd_7d: 0, drains_24h: 0 },
    contracts: raw.contracts || [],
    drains: raw.drains || [],
    operators: raw.operators || [],
    families: raw.families || [],
    deployers: raw.deployers || [],
    vasps: raw.vasps || [],
    daily: raw.daily || [],
    clusters: raw.clusters || [],
    freezable: Array.isArray(raw.freezable) ? raw.freezable : undefined,
    freezable_total: raw.freezable_total,
  }
  CHAINS = data.chains
  const gen = Date.parse(data.generated_at)
  const now = Number.isFinite(gen) ? gen : Date.now()

  // a contract row without its own family_name borrows the one in families[]
  const famMeta = new Map(data.families.map(f => [f.family, f]))
  const cases: Case[] = data.contracts.map(c0 => {
    const fm = c0.family && !c0.family_name ? famMeta.get(c0.family) : undefined
    const c = fm?.family_name ? { ...c0, family_name: fm.family_name, family_name_source: fm.family_name_source } : c0
    const isWallet = walletKind(c)
    return {
      ...c,
      labels: c.labels || [],
      payouts: c.payouts || [],
      vasp_links: c.vasp_links || [],
      evidence: c.evidence || [],
      cross_chain: c.cross_chain || [],
      usd: c.usd || 0,
      deployer: c.deployer || { address: null, tx: null, via: 'unknown', factory: null, block: null, funder: null, funder_entity: null, funder_tx: null, other_contracts: 0 },
      key: caseKey(c.chain, c.address),
      drainList: [],
      isWallet,
      title: caseTitle(c, isWallet),
      famLabel: c.family ? famLabel(c.family, c.family_name, c.family_name_source) : null,
      famSource: c.family ? (c.family_name && c.family_name_source !== 'hash' ? c.family_name_source || null : V_SRC(c.family)) : null,
      caseNo: 'DW-' + chainShort(c.chain).toUpperCase().slice(0, 3) + '-' + c.address.slice(-4).toUpperCase(),
    }
  })
  const byKey = new Map(cases.map(c => [c.key, c]))
  const drains: DrainRow[] = data.drains.map(d => {
    const key = caseKey(d.chain, d.drainer)
    const c = byKey.get(key)
    const row = { ...d, t: Date.parse(d.ts), tier: c ? c.tier : null, key }
    if (c) c.drainList.push(row)
    return row
  })
  cases.sort((a, b) => TIER_RANK[a.tier] - TIER_RANK[b.tier] || Date.parse(b.last_seen) - Date.parse(a.last_seen))

  // families (kit radar)
  const groups = new Map<string, Case[]>()
  cases.forEach(c => {
    const k = c.family || ''
    if (!groups.has(k)) groups.set(k, [])
    groups.get(k)!.push(c)
  })
  const fams: Family[] = [...groups.entries()]
    .map(([k, cs]) => {
      const profile = methodProfile(cs)
      const meta = famMeta.get(k)
      const named = meta?.family_name ? meta : cs.find(c => c.family_name)
      const nm = named ? famLabel(k, named.family_name, named.family_name_source) : famName(k || null)
      return {
        key: k,
        name: nm,
        source: k ? (named && named.family_name_source !== 'hash' && nm !== famName(k) ? named.family_name_source || null : V_SRC(k)) : null,
        blurb: famBlurb(k || null),
        contracts: cs.slice().sort((a, b) => TIER_RANK[a.tier] - TIER_RANK[b.tier] || b.usd - a.usd),
        usd: cs.reduce((s, c) => s + c.usd, 0),
        d7: cs.reduce((s, c) => s + c.drainList.filter(d => d.t > now - 7 * DAY).length, 0),
        profile,
        axes: profile.filter(p => p.value > 0).length,
      }
    })
    .sort((a, b) => (a.key ? 0 : 1) - (b.key ? 0 : 1) || b.usd - a.usd)

  // search index over every address and transaction in the data
  const index: Model['index'] = []
  const add = (value: string | null | undefined, role: string, key: string) => {
    if (value) index.push({ v: norm(value), value, role, key })
  }
  cases.forEach(c => {
    add(c.address, c.isWallet ? 'the flagged wallet' : 'the flagged contract', c.key)
    c.payouts.forEach(p => add(p.wallet, 'payout wallet (' + p.role + ')', c.key))
    add(c.deployer.address, 'deployer', c.key)
    add(c.deployer.factory, 'factory', c.key)
    add(c.deployer.funder, 'funded the deployer', c.key)
    add(c.deployer.tx, 'creation transaction', c.key)
    c.vasp_links.forEach(v => {
      add(v.counterparty, (v.entity || 'exchange') + (v.kind === 'deposit_sweep' ? ' deposit address' : ' address'), c.key)
      add(v.tx, 'transaction to ' + (v.entity || 'an exchange'), c.key)
    })
    c.evidence.forEach(e => add(e.tx, 'evidence transaction', c.key))
  })
  drains.forEach(d => {
    if (!byKey.has(d.key)) return
    add(d.victim, 'victim', d.key)
    add(d.recipient, 'received a drain', d.key)
    add(d.tx, 'drain transaction', d.key)
  })

  // headline: only confirmed and strong subjects (T3 leads such as custodial sweeps stay out, as in render.py)
  const strong = cases.filter(c => c.tier !== 'T3')
  const seen = new Set<string>()
  let surfaced = 0
  strong.forEach(c =>
    c.vasp_links.forEach(v => {
      if (v.role === 'deployer' || !v.usd) return
      const id = (v.tx || '') + v.counterparty
      if (seen.has(id)) return
      seen.add(id)
      surfaced += v.usd
    }),
  )
  const headline = {
    usd: strong.reduce((s, c) => s + c.usd, 0),
    victims: strong.reduce((s, c) => s + (c.victims || 0), 0),
    drainers: strong.length,
    surfaced,
    suspects: cases.length - strong.length,
  }
  const order = ['eth', 'bsc', 'base', 'tron']
  const chains = Object.entries(data.chains).sort((a, b) => (order.indexOf(a[0]) + 99) % 99 - (order.indexOf(b[0]) + 99) % 99)
  const freezable = data.freezable
    ? data.freezable.slice().sort((a, b) => (a.already_frozen ? 1 : 0) - (b.already_frozen ? 1 : 0) || (b.usd || 0) - (a.usd || 0))
    : null
  const freezeByCase = new Map<string, { usd: number; rows: Freezable[] }>()
  ;(freezable || []).forEach(f => {
    const c = byKey.get(caseKey(f.chain, f.drainer)) ||
      cases.find(x => x.chain === f.chain && x.address.toLowerCase() === (f.drainer || '').toLowerCase())
    const k = c ? c.key : caseKey(f.chain, f.drainer)
    const g = freezeByCase.get(k) || { usd: 0, rows: [] }
    g.rows.push(f)
    if (!f.already_frozen) g.usd += f.usd || 0
    freezeByCase.set(k, g)
    add(f.address, 'holds freezable ' + (f.symbol || 'stablecoins'), k)
  })
  return { data, now, cases, byKey, drains, chains, fams, index, headline, freezable, freezeByCase }
}

export function search(m: Model, q: string): SearchHit[] {
  const s = norm(q.trim())
  if (s.length < 3) return []
  const out: SearchHit[] = []
  const dup = new Set<string>()
  for (const e of m.index) {
    if (!e.v.includes(s)) continue
    const id = e.key + '|' + e.value + '|' + e.role
    if (dup.has(id)) continue
    dup.add(id)
    out.push({ key: e.key, value: e.value, role: e.role })
    if (out.length >= 60) break
  }
  return out
}
