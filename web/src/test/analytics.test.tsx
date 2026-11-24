// Analytics tab: ranking, aggregation, CSV and tab routing (with tests/fixtures/sample_data.json and a hand-made model).
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import App from '@/App'
import {
  DEFAULT_FILTER, atRisk, drainWindow, fmtAllowance, freezeHint, freezeRows, freezeSummary, drainerRows, fmtDuration, parseRoute, perChainSeries, recipients, sortRows, summarize, toCSV,
} from '@/lib/analytics'
import { ago, toMs } from '@/lib/format'
import { buildModel } from '@/lib/model'
import { famLabel } from '@/lib/vocab'
import { walletFile } from '@/lib/wallet'
import type { Contract, DataJson, Drain } from '@/lib/types'

const fixture = JSON.parse(readFileSync(resolve(import.meta.dirname, '../../../tests/fixtures/sample_data.json'), 'utf8')) as DataJson

const NOW = '2026-11-24T12:00:00Z'
const dep = { address: null, tx: null, via: 'unknown', factory: null, block: null, funder: null, funder_entity: null, funder_tx: null, other_contracts: 0 }
const C = (o: Partial<Contract> & Pick<Contract, 'address'>): Contract => ({
  chain: 'eth', tier: 'T1', score: 90, source: 'detector', family: null, labels: [], first_seen: '2026-11-20T00:00:00Z', last_seen: '2026-11-24T10:00:00Z',
  victims: 1, drains: 1, usd: 0, code_size: 100, verified: null, payouts: [], deployer: dep, vasp_links: [], evidence: [], ...o,
})
const D = (o: Partial<Drain> & Pick<Drain, 'drainer' | 'ts'>): Drain => ({
  chain: 'eth', tx: '0x' + Math.random().toString(16).slice(2), victim: '0xv', token: null, symbol: 'USDT', amount: '1', usd: 10, recipient: null, ...o,
})
const base: DataJson = {
  generated_at: NOW, chains: {}, totals: { tiers: { T1: 0, T2: 0, T3: 0 }, victims_24h: 0, usd_24h: 0, usd_7d: 0, drains_24h: 0 },
  contracts: [], drains: [], operators: [], families: [], deployers: [], vasps: [], daily: [], clusters: [],
}
const shared = '0xc011ec7000000000000000000000000000000001'
const mk = () => buildModel({
  ...base,
  contracts: [
    C({ address: '0xa', usd: 500, drains: 5, victims: 4, payouts: [{ wallet: shared, role: 'collector', share: 0, txs: 3 }],
      vasp_links: [{ subject: '0xa', role: 'drainer', counterparty: '0xdep', kind: 'deposit_sweep', entity: 'Binance', category: 'cex', tx: '0x1', tx_in: null, ts: NOW, amount: '1', symbol: 'USDT', usd: 120, confidence: 'high' }] }),
    C({ address: '0xb', usd: 9000, drains: 2, victims: 2, first_seen: '2026-11-24T08:00:00Z', payouts: [{ wallet: shared, role: 'collector', share: 0, txs: 1 }, { wallet: '0xaff', role: 'affiliate', share: 0.8, txs: 2 }] }),
    C({ address: '0xc', tier: 'T2', chain: 'bsc', usd: 300, last_seen: '2026-11-10T00:00:00Z' }),
    C({ address: '0xd', tier: 'T3', usd: 99999 }),
    C({ address: '0xe', tier: 'T2', usd: 0, drains: 7 }),
  ],
  drains: [
    D({ drainer: '0xa', ts: '2026-11-24T09:10:00Z', usd: 100, recipient: shared }),
    D({ drainer: '0xa', ts: '2026-11-24T11:20:00Z', usd: null, recipient: '0xa' }),
    D({ drainer: '0xb', ts: '2026-11-24T11:30:00Z', usd: 50, recipient: shared }),
    D({ drainer: '0xc', chain: 'bsc', ts: '2026-11-10T00:00:00Z', usd: 7 }),
  ],
  operators: [{ chain: 'eth', wallet: shared, drainers: 2, affiliates: 0, usd: 4000 }],
})

afterEach(() => { cleanup(); history.replaceState(null, '', '/') })

describe('ranking', () => {
  it('defaults to T1+T2 active in 7 days, ranked by USD', () => {
    const rows = drainerRows(mk(), DEFAULT_FILTER)
    expect(rows.map(r => r.c.address)).toEqual(['0xb', '0xa', '0xe'])
    expect(rows.map(r => r.rank)).toEqual([1, 2, 3])
    expect(rows[1].unpriced).toBe(1)
    expect(rows[1].exposure).toEqual([{ entity: 'Binance', usd: 120, links: 1 }])
    expect(rows[0].duration).toBe(3.5 * 3600e3) // last activity = the 11:30 drain, later than last_seen
    expect(rows[0].recipients[0].wallet).toBe('0xaff') // sorted by share
  })
  it('filters by window, chain and tier', () => {
    const m = mk()
    expect(drainerRows(m, { ...DEFAULT_FILTER, window: 'all' }).map(r => r.c.address)).toContain('0xc')
    expect(drainerRows(m, { ...DEFAULT_FILTER, window: '24h' }).map(r => r.c.address)).not.toContain('0xc')
    expect(drainerRows(m, { ...DEFAULT_FILTER, window: 'all', chain: 'bsc' }).map(r => r.c.address)).toEqual(['0xc'])
    expect(drainerRows(m, { ...DEFAULT_FILTER, tiers: ['T3'] }).map(r => r.c.address)).toEqual(['0xd'])
  })
  it('sorts by any numeric column, keeping missing values last', () => {
    const rows = drainerRows(mk(), DEFAULT_FILTER)
    expect(sortRows(rows, 'drains', 'desc').map(r => r.c.address)).toEqual(['0xe', '0xa', '0xb'])
    expect(sortRows(rows, 'usd', 'asc').map(r => r.c.address)).toEqual(['0xe', '0xa', '0xb'])
    expect(sortRows(rows, 'exposure', 'desc')[0].c.address).toBe('0xa')
    rows[0].start = NaN
    expect(sortRows(rows, 'start', 'asc').at(-1)!.c.address).toBe('0xb')
    expect(sortRows(rows, 'start', 'desc').at(-1)!.c.address).toBe('0xb')
  })
  it('summarizes the selection', () => {
    const s = summarize(drainerRows(mk(), DEFAULT_FILTER))
    expect(s).toMatchObject({ drainers: 3, usd: 9500, victims: 7, unpriced: 1 })
    expect(s.top3Share).toBe(1)
  })
})

describe('aggregation', () => {
  it('aggregates recipients across drainers, using operators[] for the full-history value', () => {
    const m = mk()
    const recs = recipients(m, drainerRows(m, DEFAULT_FILTER))
    expect(recs[0].wallet).toBe(shared)
    expect(recs[0].drainers.map(c => c.address).sort()).toEqual(['0xa', '0xb'])
    expect(recs[0].usd).toBe(4000)
    expect(recs[0].basis).toBe('full')
    // the drainer sending to itself is not a recipient
    expect(recs.some(r => r.wallet === '0xa')).toBe(false)
  })
  it('buckets USD per chain by 10 minutes for a short window', () => {
    const m = mk()
    const s = perChainSeries(drainerRows(m, DEFAULT_FILTER))
    expect(s.bucket).toBe('10 minutes')
    expect(s.chains).toEqual(['eth'])
    expect(s.total).toBe(150)
    expect(s.rows.reduce((a, r) => a + r.eth, 0)).toBe(150)
    expect(perChainSeries(drainerRows(m, { ...DEFAULT_FILTER, window: 'all' })).bucket).toBe('day')
    expect(drainWindow(m).n).toBe(4)
  })
  it('exports the visible rows as CSV with escaping', () => {
    const m = mk()
    const csv = toCSV(drainerRows(m, DEFAULT_FILTER)).trim().split('\r\n')
    expect(csv[0].split(',')[0]).toBe('rank')
    expect(csv.length).toBe(4)
    expect(csv[1]).toContain('0xb')
    expect(csv[1]).toContain('0xaff affiliate 80%; ' + shared + ' collector')
    expect(toCSV([{ ...drainerRows(m, DEFAULT_FILTER)[0], c: { ...m.cases[0], title: '=A, "b"' } }])).toContain('"=A, ""b"""')
  })
  it('reads epoch seconds, epoch ms and ISO times', () => {
    expect(toMs(1795526327)).toBe(1795526327000)
    expect(toMs('1795526327')).toBe(1795526327000)
    expect(toMs(1795526327000)).toBe(1795526327000)
    expect(toMs('2026-11-24T12:00:00Z')).toBe(Date.parse('2026-11-24T12:00:00Z'))
    expect(ago(1795526327, 1795526327000 + 2 * 3600e3)).toBe('2 h ago')
    expect(famLabel('f_c620df', ' ', 'contract_name')).toBe('Code family c620df')
  })
  it('formats durations', () => {
    expect(fmtDuration(30e3)).toBe('under 1 min')
    expect(fmtDuration(2 * 3600e3)).toBe('2 h')
    expect(fmtDuration(26 * 3600e3)).toBe('1 d 2 h')
    expect(fmtDuration(NaN)).toBe('unknown')
  })
  it('works on the fixture', () => {
    const m = buildModel(fixture)
    const rows = drainerRows(m, { ...DEFAULT_FILTER, window: 'all' })
    expect(rows.length).toBe(m.cases.filter(c => c.tier !== 'T3').length)
    for (let i = 1; i < rows.length; i++) expect(rows[i - 1].usd).toBeGreaterThanOrEqual(rows[i].usd)
  })
})

describe('family names', () => {
  it('uses family_name as the primary label with its source, falling back to the hash name', () => {
    const m = buildModel({ ...base, contracts: [
      C({ address: '0x1', family: 'f_abc123', family_name: 'PermitSweeper', family_name_source: 'contract_name' }),
      C({ address: '0x2', family: 'f_abc123' }),
      C({ address: '0x3', family: 'f_def456' }),
      C({ address: '0x4', family: 'f_0a0a0a', family_name: 'f_0a0a0a', family_name_source: 'hash' }),
    ], families: [{ family: 'f_def456', members: 1, seed_members: 0, chains: ['eth'], family_name: 'claim()+multicall', family_name_source: 'functions' }] })
    const by = (a: string) => m.cases.find(c => c.address === a)!
    expect(by('0x1').title).toBe('PermitSweeper')
    expect(by('0x1').famSource).toBe('contract_name')
    expect(by('0x3').title).toBe('claim()+multicall') // borrowed from families[]
    expect(by('0x3').famSource).toBe('functions')
    expect(by('0x4').famLabel).toBe('Code family 0a0a0a')
    expect(by('0x4').famSource).toBe('hash')
    const fam = (k: string) => m.fams.find(f => f.key === k)!
    expect(fam('f_abc123')).toMatchObject({ name: 'PermitSweeper', source: 'contract_name' })
    expect(fam('f_def456')).toMatchObject({ name: 'claim()+multicall', source: 'functions' })
    expect(fam('f_0a0a0a')).toMatchObject({ name: 'Code family 0a0a0a', source: 'hash' })
  })
})

describe('freezable', () => {
  const F = (o: Record<string, unknown>) => ({ chain: 'eth', address: '0xh1', role: 'collector', drainer: '0xa', drainer_tier: 'T1', token: '0xdac', symbol: 'USDT', issuer: 'Tether', balance: '100', usd: 100, already_frozen: false, checked_at: '2026-11-24T11:00:00Z', ...o })
  it('is null when data.json has no freezable field, and aggregates per drainer when it has', () => {
    expect(mk().freezable).toBeNull()
    expect(freezeSummary(mk())).toBeNull()
    const m = buildModel({ ...base, contracts: [C({ address: '0xa' })], freezable: [
      F({}), F({ address: '0xh2', symbol: 'USDC', issuer: 'Circle', usd: 50 }), F({ address: '0xh3', usd: 70, already_frozen: true }),
    ] as never })
    expect(m.freezable!.map(f => f.address)).toEqual(['0xh1', '0xh2', '0xh3'])
    expect(m.freezeByCase.get('eth:0xa')!.usd).toBe(150)
    const s = freezeSummary(m)!
    expect(s).toMatchObject({ usd: 150, frozen: 70, n: 2, symbols: ['USDC', 'USDT'] })
    expect(s.byIssuer).toEqual([['Tether', 100], ['Circle', 50]])
    const t = freezeSummary(buildModel({ ...base, freezable: [F({})] as never, freezable_total: { Tether: 900 } }))!
    expect(t.byIssuer).toEqual([['Tether', 900]])
    expect(freezeHint('Tether')).toMatch(/law enforcement/)
    expect(freezeHint(null, 'USDC')).toMatch(/Circle/)
  })
  it('orders by the part of a balance that drains can explain, and flags untraced balances', () => {
    const m = buildModel({ ...base, contracts: [C({ address: '0xa', usd: 801 }), C({ address: '0xb', usd: 5000 })], freezable: [
      F({ address: '0xbig', drainer: '0xa', usd: 39141 }), F({ address: '0xmid', drainer: '0xb', usd: 4000 }), F({ address: '0xsmall', drainer: '0xa', usd: 500 }),
    ] as never })
    const r = freezeRows(m)
    // 0xa took 801 in total: the largest wallet absorbs it, the second wallet of the same drainer gets nothing traceable
    expect(r.map(x => [x.f.address, x.traceable, x.untraced])).toEqual([['0xmid', 4000, false], ['0xbig', 801, true], ['0xsmall', 0, false]])
    expect(freezeRows(m, 'balance')[0].f.address).toBe('0xbig')
    expect(freezeSummary(m)!.traceable).toBe(4801)
  })
  it('shows "Not computed yet" without the field and the table with it', async () => {
    history.replaceState(null, '', '#analytics')
    render(<App data={fixture} />)
    expect((await screen.findAllByText(/Not computed yet/, undefined, { timeout: 15000 })).length).toBe(2) // freezable + open allowances
    cleanup()
    const c = fixture.contracts[0]
    render(<App data={{ ...fixture, freezable: [F({ chain: c.chain, drainer: c.address, drainer_tier: c.tier, usd: 1234 })] as never }} />)
    expect(await screen.findByText(/sits on drainer-linked wallets right now/, undefined, { timeout: 15000 })).toBeTruthy()
    expect(document.querySelectorAll('[data-frz-row]').length).toBe(1)
  })
})

describe('approval-only subjects and open allowances', () => {
  const ev = [{ type: 'approval_fingerprint', tx: '0xapp', ts: '2026-11-23T16:48:47Z',
    detail: 'victim 0x378d0bc33a9506faeaf12e7bcff32ab0fcc63bb9 approved token 0xdac17f958d2ee523a2206206994597c13d831ec7 with the ms_drainer kit amount (hard-coded approval value: kit fingerprint)' }]
  const spender = C({ address: '0x81097f6fea74e4540c83daf01ae24c0f7e8df7a6', labels: ['approval_fingerprint'], evidence: ev, drains: 0, usd: 0, victims: 1, code_size: null })
  it('flags approval-only cases and parses the approval from the evidence', () => {
    const m = buildModel({ ...base, contracts: [spender, C({ address: '0xa', usd: 5, drains: 1, labels: ['approval_fingerprint'] })] })
    const c = m.cases.find(x => x.address === spender.address)!
    expect(c.approvalOnly).toBe(true)
    expect(c.approvals).toEqual([{ victim: '0x378d0bc33a9506faeaf12e7bcff32ab0fcc63bb9', token: '0xdac17f958d2ee523a2206206994597c13d831ec7', tx: '0xapp', ts: '2026-11-23T16:48:47Z' }])
    expect(m.cases.find(x => x.address === '0xa')!.approvalOnly).toBe(false)
    expect(atRisk(m)).toBeNull()
  })
  it('lists open allowances that were not pulled, largest first', () => {
    const oa = (o: Record<string, unknown>) => ({ victim: '0xv1', token: '0xdac17f958d2ee523a2206206994597c13d831ec7', symbol: null, allowance: 'unlimited', victim_balance: '50', usd_at_risk: 50, pulled: false, checked_at: NOW, ...o })
    const m = buildModel({ ...base, contracts: [{ ...spender, open_allowances: [oa({}), oa({ victim: '0xv2', usd_at_risk: 900, allowance: String(2n ** 256n - 1n) }), oa({ victim: '0xv3', pulled: true })] }] })
    const r = atRisk(m)!
    expect(r.map(x => x.victim)).toEqual(['0xv2', '0xv1'])
    expect(r[0].allowance).toBe('unlimited')
    expect(r[0].symbol).toBe('USDT')
    expect(fmtAllowance('1500')).toBe('1,500')
  })
  it('the spread says nothing was taken yet and explains why an empty spender is dangerous', async () => {
    history.replaceState(null, '', '#eth:' + spender.address)
    render(<App data={{ ...base, contracts: [spender] }} />)
    await waitFor(() => expect(document.querySelector('[data-case]')).toBeTruthy(), { timeout: 15000 })
    const page = document.querySelector('[data-case]')!.textContent!
    expect(page).toMatch(/1 wallet gave this address permission to spend its USDT/)
    expect(page).toMatch(/nothing has been taken yet/)
    expect(page).not.toMatch(/lost/)
    expect(page).toContain('Confirmed kit spender (approval fingerprint)')
    expect(page).toMatch(/Still exposed/)
    expect(page).toMatch(/Not checked yet/)
  })
})

describe('wallet case files', () => {
  const coll = '0xc011ec7000000000000000000000000000000001'
  it('parses #wallet:chain:address', () => {
    expect(parseRoute('#wallet:tron:TWJbeT1111111111111111111111111111')).toEqual({ tab: null, caseRef: null, walletRef: { chain: 'tron', address: 'TWJbeT1111111111111111111111111111' } })
  })
  it('falls back to payouts and published drains without the wallets aggregate', () => {
    const w = walletFile(mk(), 'eth', coll)
    expect(w.full).toBe(false)
    expect(w.roles).toEqual(['collector'])
    expect(w.drainers.map(d => [d.drainer, d.usd, d.txs])).toEqual([['0xa', 100, 1], ['0xb', 50, 1]])
    expect(w.nIn).toBe(2)
    expect(w.totalIn).toBe(150)
    expect(w.known).toBe(true)
    expect(walletFile(mk(), 'eth', '0xnobody').known).toBe(false)
  })
  it('uses the backend aggregate when present', () => {
    const m = buildModel({ ...base, contracts: [C({ address: '0xa', usd: 500 })], wallets: { ['eth:' + coll]: {
      roles: ['collector'], drainers: [{ drainer: '0xa', tier: 'T1', role: 'collector', share: 0, usd: 900, txs: 60, first: '2026-11-01T00:00:00Z', last: '2026-11-24T00:00:00Z' }],
      inflows: [{ tx: '0x1', ts: '2026-11-24T00:00:00Z', victim: '0xv', drainer: '0xa', token: null, symbol: 'USDT', amount: '5', usd: 5 }],
      outflows_known: [], first_in: '2026-11-01T00:00:00Z', last_in: '2026-11-24T00:00:00Z', total_in_usd: 900, n_in: 60 } } })
    const w = walletFile(m, 'eth', coll)
    expect(w).toMatchObject({ full: true, nIn: 60, totalIn: 900, bestTier: 'T1' })
    expect(w.drainers[0].c?.address).toBe('0xa')
  })
  it('opens from #wallet: and from a freezable row; no "How to request" column', async () => {
    const c = fixture.contracts[0]
    const w = c.payouts[0].wallet
    history.replaceState(null, '', '#wallet:' + c.chain + ':' + w)
    render(<App data={fixture} />)
    await waitFor(() => expect(document.querySelector('[data-wallet="' + c.chain + ':' + w + '"]')).toBeTruthy(), { timeout: 15000 })
    expect(document.querySelector('[data-wallet]')!.textContent).toMatch(/Linked drainers/)
    cleanup()
    history.replaceState(null, '', '#analytics')
    render(<App data={{ ...fixture, freezable: [{ chain: c.chain, address: w, role: 'collector', drainer: c.address, drainer_tier: c.tier, token: null, symbol: 'USDT', issuer: 'Tether', balance: '10', usd: 10, already_frozen: false, checked_at: 1795526327 }] }} />)
    const row = await waitFor(() => { const r = document.querySelector('[data-frz-row]') as HTMLElement; expect(r).toBeTruthy(); return r }, { timeout: 15000 })
    expect(screen.queryByText('How to request')).toBeNull()
    fireEvent.click(row)
    await waitFor(() => expect(document.querySelector('[data-wallet]')).toBeTruthy(), { timeout: 15000 })
    expect(location.hash).toBe('#wallet:' + c.chain + ':' + w)
    fireEvent.click(screen.getByRole('button', { name: 'Close file' }))
    await waitFor(() => expect(document.querySelector('[data-wallet]')).toBeNull())
    expect(location.hash).toBe('#analytics')
  })
})

describe('tab routing', () => {
  it('parses tabs, case links and section anchors', () => {
    expect(parseRoute('#analytics')).toEqual({ tab: 'analytics', caseRef: null })
    expect(parseRoute('#overview')).toEqual({ tab: 'overview', caseRef: null })
    expect(parseRoute('')).toEqual({ tab: 'overview', caseRef: null })
    expect(parseRoute('#flow')).toEqual({ tab: 'overview', caseRef: null })
    expect(parseRoute('#eth:0xAbC')).toEqual({ tab: null, caseRef: { chain: 'eth', address: '0xAbC' } })
  })
  it('opens #analytics, switches tabs and keeps case links working from it', async () => {
    history.replaceState(null, '', '#analytics')
    render(<App data={fixture} />)
    expect(screen.getByRole('tab', { name: 'Analytics' }).getAttribute('aria-selected')).toBe('true')
    expect(await screen.findByRole('heading', { name: 'Drainers active now' }, { timeout: 15000 })).toBeTruthy()
    expect(screen.queryByRole('heading', { name: 'Case files' })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'All time' }))
    const row = await waitFor(() => { const r = document.querySelector('[data-rank-row]') as HTMLElement; expect(r).toBeTruthy(); return r })
    fireEvent.click(row)
    await waitFor(() => expect(document.querySelector('[data-case="' + row.dataset.rankRow + '"]')).toBeTruthy(), { timeout: 15000 })
    expect(location.hash).toBe('#' + row.dataset.rankRow)
    fireEvent.click(screen.getByRole('button', { name: 'Close file' }))
    await waitFor(() => expect(document.querySelector('[data-case]')).toBeNull())
    expect(location.hash).toBe('#analytics')
    expect(screen.getByRole('heading', { name: 'Drainers active now' })).toBeTruthy()
    fireEvent.click(screen.getByRole('tab', { name: 'Overview' }))
    expect(location.hash).toBe('#overview')
    expect(screen.getByRole('heading', { name: 'Case files' })).toBeTruthy()
  })
  it('a case deep link opens over the overview', async () => {
    const c = fixture.contracts[2]
    history.replaceState(null, '', '#' + c.chain + ':' + c.address)
    render(<App data={fixture} />)
    expect(screen.getByRole('tab', { name: 'Overview', hidden: true }).getAttribute('aria-selected')).toBe('true')
    await waitFor(() => expect(document.querySelector('[data-case="' + c.chain + ':' + c.address + '"]')).toBeTruthy(), { timeout: 15000 })
  })
})
