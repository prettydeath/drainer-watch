import { useEffect, useMemo, useRef, useState } from 'react'
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, LabelList, XAxis, YAxis } from 'recharts'
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from '@/components/ui/chart'
import {
  DEFAULT_FILTER, WINDOWS, atRisk, drainWindow, fmtAllowance, freezeHint, freezeHintShort, freezeSummary, drainerRows, fmtDuration, perChainSeries, recipients, sortRows, summarize, toCSV, windowOf,
  type DrainerRow, type Filter, type Recipient, type SortKey,
} from '@/lib/analytics'
import { DAY, ago, fmtDay, fmtInt, fmtStamp, fmtTime, fmtUSD, mid, plural } from '@/lib/format'
import type { Case, Model } from '@/lib/model'
import type { Freezable, Tier } from '@/lib/types'
import { TIER_NAME, TIER_ORDER, chainLong, chainShort, famSourceNote, roleInfo } from '@/lib/vocab'
import { Addr, tv, useMedia } from './shared'

const PAGE = 25
const TOP_BARS = 15
const TOP_GANTT = 15
const TOP_RECIPIENTS = 12

const CHAIN_COLOR: Record<string, string> = { eth: 'var(--chart-1)', bsc: 'var(--t2)', base: 'var(--chart-3)', tron: 'var(--t1)' }
const chainColor = (c: string, i: number) => CHAIN_COLOR[c] || ['var(--chart-2)', 'var(--chart-4)', 'var(--t3)'][i % 3]

const tierPhrase = (ts: Tier[]) => {
  const xs = TIER_ORDER.filter(t => ts.includes(t))
  if (xs.length === 3) return 'tracked'
  const n = xs.map(t => TIER_NAME[t].toLowerCase())
  return n.length === 2 ? n[0] + ' and ' + n[1] : n[0] || 'no'
}
const css = (o: Record<string, string>) => o as unknown as React.CSSProperties
const kitLine = (c: Case) => {
  const parts: string[] = []
  if (c.famLabel) parts.push(c.famLabel + (c.famSource && c.famSource !== 'hash' ? ' (' + famSourceNote(c.famSource) + ')' : ''))
  if (c.contract_name && c.contract_name !== c.famLabel) parts.push(c.contract_name)
  if (!parts.length) parts.push(c.title)
  if (c.isWallet && !/wallet/i.test(parts[0])) parts.push('wallet')
  return parts.join(', ')
}


/* ---------------- open allowances ---------------- */

function AtRiskNow({ model, onOpen }: { model: Model; onOpen: (c: Case) => void }) {
  const rows = useMemo(() => atRisk(model), [model])
  const [n, setN] = useState(8)
  const head = <div className="sect-h"><h2>At risk now</h2><p>Approvals to drainer spenders that are still open: the tokens can be pulled at any moment.</p></div>
  if (!rows) return <section className="sect" id="at-risk">{head}<div className="card card-pad margin"><p className="empty">Not computed yet: this data.json predates the open-allowance check.</p></div></section>
  const usd = rows.reduce((s, r) => s + (r.usd || 0), 0)
  const victims = new Set(rows.map(r => r.victim.toLowerCase())).size
  return (
    <section className="sect" id="at-risk">
      {head}
      <div className="card card-pad frz">
        <p className="frz-lead">{rows.length ? <><b className="num">{fmtUSD(usd)}</b> sits in {plural(victims, 'wallet')} that still let a drainer spend their tokens ({plural(rows.length, 'open approval')}); revoking an approval closes it.</> : 'No open approval to a tracked drainer at the last check.'}</p>
        {rows.length ? (
          <div className="rank-wrap">
            <table className="ledger rank">
              <thead><tr><th>Victim wallet</th><th>Spender</th><th>Token</th><th className="r">Allowance</th><th className="r">Balance</th><th className="r">At risk</th><th>Checked</th></tr></thead>
              <tbody>
                {rows.slice(0, n).map((r, i) => (
                  <tr key={r.c.key + r.victim + r.token} className="row" data-risk-row={r.victim} style={css({ '--tc': tv(r.c.tier) })}>
                    <td className="who" data-l="Victim wallet" data-rank={i + 1} data-tier={(r.symbol || 'token') + ' on ' + chainLong(r.c.chain)}><Addr value={r.victim} chain={r.c.chain} link /> <span className="muted small">{chainShort(r.c.chain)}</span></td>
                    <td data-l="Spender"><span className="tg">{r.c.tier}</span> <button className="linkbtn mono small" onClick={() => onOpen(r.c)}>{mid(r.c.address, 6, 4)}</button></td>
                    <td data-l="Token"><b>{r.symbol || <Addr value={r.token} chain={r.c.chain} />}</b></td>
                    <td className="r" data-l="Allowance">{r.allowance}</td>
                    <td className="r num" data-l="Balance">{r.balance == null ? <span className="muted">unknown</span> : fmtAllowance(r.balance)}</td>
                    <td className="r" data-l="At risk"><b className="num">{r.usd == null ? <span className="muted">unpriced</span> : fmtUSD(r.usd)}</b></td>
                    <td data-l="Checked">{r.checked ? <span title={fmtStamp(r.checked)}>{ago(r.checked, model.now)}</span> : <span className="muted">unknown</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {rows.length > n ? <button className="btn more-btn" onClick={() => setN(x => x + 15)}>Show {Math.min(15, rows.length - n)} more of {rows.length - n}</button> : null}
          </div>
        ) : null}
        <p className="note-row"><span>An approval stays valid until the owner revokes it; explorers list a wallet's approvals in their token approval checker. Balances are a snapshot at the time shown.</span></p>
      </div>
    </section>
  )
}

/* ---------------- freezable now ---------------- */

const ISSUER_COLOR = (i: string | null | undefined) => (/tether/i.test(i || '') ? 'var(--chart-1)' : /circle/i.test(i || '') ? 'var(--t3)' : 'var(--chart-3)')
const issuerOf = (f: Freezable) => f.issuer || (/usdt/i.test(f.symbol || '') ? 'Tether' : /usdc/i.test(f.symbol || '') ? 'Circle' : 'Unknown issuer')
const fmtBal = (b: Freezable['balance']) => {
  const n = typeof b === 'number' ? b : Number(b)
  return b == null || b === '' ? 'unknown' : Number.isFinite(n) ? n.toLocaleString('en-US', { maximumFractionDigits: 2 }) : String(b)
}
const frzConfig = { usd: { label: 'Freezable', color: 'var(--chart-1)' } } satisfies ChartConfig

function FreezableNow({ model, onOpen }: { model: Model; onOpen: (c: Case) => void }) {
  const s = useMemo(() => freezeSummary(model), [model])
  const [n, setN] = useState(10)
  const small = useMedia('(max-width: 640px)')
  const rows = model.freezable
  const head = <div className="sect-h"><h2>Freezable now</h2><p>Stablecoins on drainer-linked wallets that the issuer can still freeze.</p></div>
  if (!rows || !s)
    return <section className="sect" id="freezable">{head}<div className="card card-pad margin"><p className="empty">Not computed yet: this data.json predates the freezable-balance check. It will appear here once the scanner publishes it.</p></div></section>
  const issuerText = s.byIssuer.map(([i, u]) => fmtUSD(u) + ' on ' + i + '-freezable ' + (/tether/i.test(i) ? 'USDT' : /circle/i.test(i) ? 'USDC' : 'tokens')).join(', ')
  const data = rows.filter(f => !f.already_frozen && (f.usd || 0) > 0).slice(0, TOP_RECIPIENTS)
    .map(f => ({ id: f.chain + ':' + f.address + ':' + (f.token || f.symbol), usd: Math.round(f.usd || 0), f }))
  const ticks = new Map(data.map(d => [d.id, { addr: d.f.address, chain: d.f.chain }]))
  const h = 30 + data.length * 28
  return (
    <section className="sect" id="freezable">
      {head}
      <div className="card card-pad frz">
        {s.usd > 0 ? (
          <p className="frz-lead"><b className="num">{fmtUSD(s.usd)}</b> in {s.symbols.join('/') || 'stablecoins'} sits on drainer-linked wallets right now{issuerText ? <>; {issuerText}</> : null}.
            {s.frozen > 0 ? <> A further {fmtUSD(s.frozen)} is already frozen.</> : null}
            {Number.isFinite(s.checked) ? <span className="muted small"> Balances checked {ago(s.checked, model.now)}.</span> : null}</p>
        ) : <p className="frz-lead">{rows.length ? <>No unfrozen stablecoin balance is left on drainer-linked wallets{s.frozen > 0 ? <>; {fmtUSD(s.frozen)} is already frozen</> : null}.</> : 'No freezable stablecoin balance was found on drainer-linked wallets at the last check.'}</p>}
        {rows.length ? (
          <div className="frz-two">
            <div className="rank-wrap">
              <table className="ledger rank">
                <thead><tr><th className="r">#</th><th>Address</th><th>Linked drainer</th><th>Token</th><th className="r">Balance</th><th className="r">USD</th><th>Status</th><th>How to request</th></tr></thead>
                <tbody>
                  {rows.slice(0, n).map((f, i) => {
                    const c = model.byKey.get(f.chain + ':' + f.drainer) || model.cases.find(x => x.chain === f.chain && x.address.toLowerCase() === (f.drainer || '').toLowerCase())
                    const tier = c?.tier || f.drainer_tier
                    return (
                      <tr key={f.chain + f.address + (f.token || f.symbol) + i} className={'row' + (f.already_frozen ? ' frozen' : '')} data-frz-row={f.address} style={css({ '--tc': tv(tier) })}>
                        <td className="r rk" data-l="#">{i + 1}</td>
                        <td className="who" data-l="Address" data-rank={i + 1} data-tier={(f.symbol || '') + ' on ' + chainLong(f.chain)}>
                          <Addr value={f.address} chain={f.chain} link /> <span className="muted small">{chainShort(f.chain)}</span>
                          <span className="kit">{roleInfo(f.role)[0].toLowerCase()}</span>
                        </td>
                        <td data-l="Linked drainer">{tier ? <span className="tg">{tier}</span> : null} {c ? <button className="linkbtn mono small" onClick={() => onOpen(c)}>{mid(f.drainer, 6, 4)}</button> : <Addr value={f.drainer} chain={f.chain} />}</td>
                        <td data-l="Token"><span className="iss" style={css({ '--ic': ISSUER_COLOR(issuerOf(f)) })}><i />{f.symbol || 'token'}</span><span className="sub">{issuerOf(f)}</span></td>
                        <td className="r num" data-l="Balance">{fmtBal(f.balance)}</td>
                        <td className="r" data-l="USD"><b className="num">{f.usd == null ? <span className="muted">unpriced</span> : fmtUSD(f.usd)}</b></td>
                        <td data-l="Status">{f.already_frozen ? <span className="badge-frozen">already frozen</span> : <span className="muted">not frozen</span>}{f.checked_at ? <span className="sub" title={fmtStamp(f.checked_at)}>checked {ago(f.checked_at, model.now)}</span> : null}</td>
                        <td className="wrapc hint" data-l="How to request">{f.already_frozen ? <span className="muted">nothing to request</span> : <span title={freezeHint(issuerOf(f), f.symbol)}>{small ? freezeHint(issuerOf(f), f.symbol) : freezeHintShort(issuerOf(f), f.symbol)}</span>}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
              {rows.length > n ? <button className="btn more-btn" onClick={() => setN(x => x + 15)}>Show {Math.min(15, rows.length - n)} more of {rows.length - n}</button> : null}
            </div>
            {data.length ? (
              <div className="frz-chart">
                <h3>Largest holders</h3>
                <ChartContainer config={frzConfig} className="aspect-auto w-full" style={{ height: h }} initialDimension={{ width: 420, height: h }}>
                  <BarChart accessibilityLayer data={data} layout="vertical" margin={{ top: 4, right: 52, left: 4, bottom: 4 }}>
                    <CartesianGrid horizontal={false} strokeDasharray="2 4" />
                    <XAxis type="number" dataKey="usd" tickFormatter={v => fmtUSD(v, true)} tickLine={false} axisLine={{ stroke: 'var(--border)' }} tickCount={3} />
                    <YAxis type="category" dataKey="id" width={128} tickLine={false} axisLine={false} interval={0} tick={<AddrTick rows={ticks} />} />
                    <ChartTooltip cursor={{ fill: 'var(--muted)' }} content={<ChartTooltipContent hideIndicator
                      labelFormatter={(_, p) => { const f = (p?.[0]?.payload as { f: Freezable })?.f; return f ? (f.symbol || 'token') + ' (' + issuerOf(f) + '), ' + roleInfo(f.role)[0].toLowerCase() : '' }}
                      formatter={(v, _n, item) => <span className="flex w-full flex-col gap-0.5"><span className="flex justify-between gap-3"><span className="muted">Freezable</span><b className="num">{fmtUSD(Number(v))}</b></span><span className="mono" style={{ fontSize: 11 }}>{(item.payload as { f: Freezable }).f.address}</span></span>} />} />
                    <Bar dataKey="usd" radius={[0, 2, 2, 0]} isAnimationActive={false}>
                      {data.map(d => <Cell key={d.id} fill={ISSUER_COLOR(issuerOf(d.f))} />)}
                      <LabelList dataKey="usd" position="right" className="barlabel" formatter={(v: unknown) => fmtUSD(Number(v), true)} />
                    </Bar>
                  </BarChart>
                </ChartContainer>
                <div className="legend small">{[...new Set(data.map(d => issuerOf(d.f)))].map(i => <span key={i}><i style={{ background: ISSUER_COLOR(i) }} />{i}</span>)}</div>
              </div>
            ) : null}
          </div>
        ) : null}
        <p className="note-row"><span>Every drainer-linked wallet in the data, whatever the filter below. A balance is a snapshot at the time shown and may have moved since; whether to freeze is the issuer's decision.</span></p>
      </div>
    </section>
  )
}

/* ---------------- summary ---------------- */

function SummaryStrip({ model, rows, f, recs }: { model: Model; rows: DrainerRow[]; f: Filter; recs: Recipient[] }) {
  const s = summarize(rows)
  const w = windowOf(f.window)
  const where = f.chain === 'all' ? '' : ' on ' + chainLong(f.chain)
  const kind = tierPhrase(f.tiers)
  const top = rows[0]
  const shared = recs.find(r => r.drainers.length >= 2)
  if (!s.drainers)
    return <p className="summary">No {kind} drainer was active{where} {w.phrase}.</p>
  return (
    <div className="summary">
      <p>
        <b className="num">{fmtInt(s.drainers)}</b> {kind} {s.drainers === 1 ? 'drainer was' : 'drainers were'} active{where} {w.phrase}; since their campaigns began they have taken{' '}
        <b className="num">{fmtUSD(s.usd)}</b> from <b className="num">{fmtInt(s.victims)}</b> wallets
        {s.drainers > 3 && s.usd > 0 ? <>, and the top 3 account for <b className="num">{Math.round(s.top3Share * 100)}%</b> of it</> : null}.
        {top && top.usd > 0 ? <> The largest, <span className="mono">{mid(top.c.address)}</span> on {chainLong(top.c.chain)} ({top.c.tier}), took {fmtUSD(top.usd)} between {fmtDay(top.start)} and {fmtDay(top.last)}.</> : null}
        {shared ? <> Payout wallet <span className="mono">{mid(shared.wallet)}</span> is fed by {plural(shared.drainers.length, 'drainer')}, a sign of one operator behind them.</> : null}
      </p>
      {s.unpriced || model.drains.length >= 500 ? (
        <p className="muted small">{s.unpriced ? <>{plural(s.unpriced, 'drain')} of these drainers in the published list could not be priced and count as zero. </> : null}Totals cover each drainer's full history; drain-level details reach back only as far as the latest published drains{Number.isFinite(drainWindow(model).from) ? ', to ' + fmtStamp(drainWindow(model).from) : ''}.</p>
      ) : null}
    </div>
  )
}

/* ---------------- ranked table ---------------- */

const COLS: { key: SortKey | null; label: string; num?: boolean; cls?: string }[] = [
  { key: 'rank', label: '#', num: true },
  { key: null, label: 'Drainer' },
  { key: 'usd', label: 'Taken', num: true },
  { key: 'victims', label: 'Victims', num: true },
  { key: 'drains', label: 'Drains', num: true },
  { key: 'start', label: 'Campaign start', num: true },
  { key: 'last', label: 'Last activity', num: true },
  { key: 'duration', label: 'Duration', num: true },
  { key: 'recipients', label: 'Recipients', num: true },
  { key: 'exposure', label: 'Exchanges', num: true },
  { key: null, label: 'Cluster' },
]

function Recipients({ r }: { r: DrainerRow }) {
  const [all, setAll] = useState(false)
  if (!r.recipients.length) return <span className="muted">none recorded</span>
  const shown = all ? r.recipients : r.recipients.slice(0, 2)
  return (
    <ul className="recips">
      {shown.map(p => (
        <li key={p.wallet + p.role}>
          <Addr value={p.wallet} chain={r.c.chain} link /> <span className="muted small" title={roleInfo(p.role)[1]}>{roleInfo(p.role)[0].toLowerCase()}{p.share ? ' ' + Math.round(p.share * 100) + '%' : ''}</span>
        </li>
      ))}
      {r.recipients.length > 2 ? (
        <li><button type="button" className="linkbtn small" onClick={e => { e.stopPropagation(); setAll(a => !a) }} aria-expanded={all}>{all ? 'fewer' : '+' + (r.recipients.length - 2) + ' more'}</button></li>
      ) : null}
    </ul>
  )
}

function RankTable({ model, rows, onOpen }: { model: Model; rows: DrainerRow[]; onOpen: (c: Case) => void }) {
  const [sort, setSort] = useState<{ key: SortKey; dir: 'asc' | 'desc' }>({ key: 'rank', dir: 'asc' })
  const small = useMedia('(max-width: 640px)')
  const page = small ? 10 : PAGE
  const [n, setN] = useState(page)
  useEffect(() => setN(page), [rows, page])
  const sorted = useMemo(() => sortRows(rows, sort.key, sort.dir), [rows, sort])
  const clusters = useMemo(() => new Map(model.data.clusters.map(c => [c.cluster, c])), [model])
  const click = (k: SortKey) =>
    setSort(s => (s.key === k ? { key: k, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key: k, dir: k === 'rank' ? 'asc' : 'desc' }))
  return (
    <>
      <div className="rank-wrap">
        <table className="ledger rank">
          <thead>
            <tr>{COLS.map(col => (
              <th key={col.label} className={col.num ? 'r' : undefined} aria-sort={col.key && sort.key === col.key ? (sort.dir === 'asc' ? 'ascending' : 'descending') : undefined}>
                {col.key ? (
                  <button type="button" className="sorth" onClick={() => click(col.key!)}>
                    {col.label}<span aria-hidden="true" className="arrow">{sort.key === col.key ? (sort.dir === 'asc' ? '▲' : '▼') : '↕'}</span>
                  </button>
                ) : col.label}
              </th>
            ))}</tr>
          </thead>
          <tbody>
            {sorted.slice(0, n).map(r => {
              const c = r.c
              const cl = r.cluster ? clusters.get(r.cluster) : null
              return (
                <tr key={c.key} className="row" data-rank-row={c.key} style={css({ '--tc': tv(c.tier) })} tabIndex={0}
                  onClick={() => onOpen(c)} onKeyDown={e => { if (e.key === 'Enter' && e.target === e.currentTarget) onOpen(c) }}
                  aria-label={'Open case ' + c.caseNo + ', rank ' + r.rank}>
                  <td className="r rk" data-l="Rank">{r.rank}</td>
                  <td className="who" data-l="Drainer" data-rank={r.rank} data-tier={c.tier + ' ' + TIER_NAME[c.tier].toLowerCase() + ', ' + chainLong(c.chain)}>
                    <span className="tg">{c.tier}</span> <Addr value={c.address} chain={c.chain} h={8} t={6} link /> <span className="muted small">{chainShort(c.chain)}</span>
                    <span className="kit" title={c.family ? 'Code family hash ' + c.family : undefined}>{kitLine(c)}</span>
                  </td>
                  <td className="r" data-l="Taken"><b className="num">{r.usd ? fmtUSD(r.usd) : <span className="muted">$0</span>}</b>{r.unpriced ? <span className="sub">{r.unpriced} unpriced</span> : null}{c.approvalOnly ? <span className="sub">approval only, nothing taken yet</span> : null}{(model.freezeByCase.get(c.key)?.usd || 0) > 0 ? <span className="frz-b" title="Stablecoins on its linked wallets that the issuer can still freeze">freezable {fmtUSD(model.freezeByCase.get(c.key)!.usd, true)}</span> : null}</td>
                  <td className="r" data-l="Victims">{fmtInt(r.victims)}</td>
                  <td className="r" data-l="Drains">{fmtInt(r.drains)}</td>
                  <td className="r" data-l="Campaign start"><span title={fmtStamp(r.start)}>{fmtDay(r.start)}</span><span className="sub">{fmtTime(r.start)} UTC</span></td>
                  <td className="r" data-l="Last activity"><span title={fmtStamp(r.last)}>{ago(r.last, model.now)}</span><span className="sub">{fmtDay(r.last)}, {fmtTime(r.last)}</span></td>
                  <td className="r" data-l="Duration">{fmtDuration(r.duration)}</td>
                  <td className="wrapc" data-l="Recipients"><Recipients r={r} /></td>
                  <td className={'wrapc' + (r.exposure.length ? '' : ' nil')} data-l="Exchanges">{r.exposure.length ? r.exposure.map(e => <span key={e.entity} className="xp">{e.entity} {e.usd ? fmtUSD(e.usd, true) : <span className="muted">unpriced</span>}</span>) : <span className="muted">none seen</span>}</td>
                  <td className={r.cluster ? undefined : 'nil'} data-l="Cluster">{cl ? <span className="clu" title={plural(cl.members.length, 'drainer') + ' share ' + plural(cl.shared_wallets.length, 'payout wallet')}><span className="mono small">{cl.cluster}</span><span className="sub">{plural(cl.members.length, 'member')}</span></span> : r.cluster ? <span className="mono small">{r.cluster}</span> : <span className="muted">none</span>}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      {sorted.length > n ? <button className="btn more-btn" onClick={() => setN(x => x + page)}>Show {Math.min(page, sorted.length - n)} more of {sorted.length - n}</button> : null}
    </>
  )
}

/* ---------------- charts ---------------- */

const AddrTick = ({ x, y, payload, rows }: { x?: number; y?: number; payload?: { value: string }; rows: Map<string, { addr: string; chain: string }> }) => {
  const r = rows.get(payload?.value || '')
  if (!r) return null
  return (
    <text x={x} y={y} dy={4} textAnchor="end" className="ytick">
      <tspan className="mono">{mid(r.addr, 6, 4)}</tspan><tspan className="muted-t"> {chainShort(r.chain)}</tspan>
    </text>
  )
}

const topConfig = { usd: { label: 'Taken', color: 'var(--chart-1)' } } satisfies ChartConfig

function TopDrainers({ rows, onOpen }: { rows: DrainerRow[]; onOpen: (c: Case) => void }) {
  const data = useMemo(() => rows.filter(r => r.usd > 0).sort((a, b) => b.usd - a.usd).slice(0, TOP_BARS)
    .map(r => ({ id: r.c.key, usd: Math.round(r.usd), tier: r.c.tier, r })), [rows])
  const ticks = useMemo(() => new Map(data.map(d => [d.id, { addr: d.r.c.address, chain: d.r.c.chain }])), [data])
  if (!data.length) return <p className="empty">No drainer in this selection has a priced drain.</p>
  const h = 30 + data.length * 28
  return (
    <ChartContainer config={topConfig} className="aspect-auto w-full" style={{ height: h }} initialDimension={{ width: 560, height: h }}>
      <BarChart accessibilityLayer data={data} layout="vertical" margin={{ top: 4, right: 56, left: 4, bottom: 4 }}>
        <CartesianGrid horizontal={false} strokeDasharray="2 4" />
        <XAxis type="number" dataKey="usd" tickFormatter={v => fmtUSD(v, true)} tickLine={false} axisLine={{ stroke: 'var(--border)' }} tickCount={4} />
        <YAxis type="category" dataKey="id" width={128} tickLine={false} axisLine={false} interval={0} tick={<AddrTick rows={ticks} />} />
        <ChartTooltip cursor={{ fill: 'var(--muted)' }} content={<ChartTooltipContent hideIndicator
          labelFormatter={(_, p) => { const r = (p?.[0]?.payload as { r: DrainerRow })?.r; return r ? r.c.tier + ' ' + r.c.title + ', ' + chainLong(r.c.chain) : '' }}
          formatter={(v, _n, item) => { const r = (item.payload as { r: DrainerRow }).r; return (
            <span className="flex w-full flex-col gap-0.5"><span className="flex justify-between gap-3"><span className="muted">Taken</span><b className="num">{fmtUSD(Number(v))}</b></span><span className="flex justify-between gap-3"><span className="muted">Victims</span><b className="num">{fmtInt(r.victims)}</b></span><span className="mono" style={{ fontSize: 11 }}>{r.c.address}</span></span>
          ) }} />} />
        <Bar dataKey="usd" radius={[0, 2, 2, 0]} isAnimationActive={false} cursor="pointer" onClick={(d: unknown) => { const r = (d as { payload?: { r?: DrainerRow } })?.payload?.r; if (r) onOpen(r.c) }}>
          {data.map(d => <Cell key={d.id} fill={tv(d.tier)} />)}
          <LabelList dataKey="usd" position="right" className="barlabel" formatter={(v: unknown) => fmtUSD(Number(v), true)} />
        </Bar>
      </BarChart>
    </ChartContainer>
  )
}

function useWidth<T extends HTMLElement>(fallback: number): [React.RefObject<T | null>, number] {
  const ref = useRef<T>(null)
  const [w, setW] = useState(fallback)
  useEffect(() => {
    const el = ref.current
    if (!el || typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(es => { const x = Math.round(es[0].contentRect.width); if (x > 0) setW(x) })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  return [ref, w]
}

function Gantt({ rows, now, onOpen }: { rows: DrainerRow[]; now: number; onOpen: (c: Case) => void }) {
  const [box, width] = useWidth<HTMLDivElement>(900)
  const [hover, setHover] = useState<{ r: DrainerRow; x: number; y: number } | null>(null)
  const top = useMemo(() => rows.filter(r => Number.isFinite(r.start) && Number.isFinite(r.last))
    .sort((a, b) => b.usd - a.usd || b.drains - a.drains).slice(0, TOP_GANTT), [rows])
  if (!top.length) return <p className="empty">No campaign with a known start and last activity in this selection.</p>
  const W = Math.max(600, width), L = 132, R = 18, T = 26, RH = 26
  const Hh = T + top.length * RH + 6
  let lo = Math.min(...top.map(r => r.start)), hi = Math.max(now, ...top.map(r => r.last))
  if (hi - lo < 3600e3) lo = hi - 3600e3
  const pad = (hi - lo) * 0.02
  lo -= pad
  const xs = (t: number) => L + ((t - lo) / (hi - lo)) * (W - L - R)
  const short = hi - lo <= 2 * DAY
  const ticks = Array.from({ length: 5 }, (_, i) => lo + pad + ((hi - lo - pad) * i) / 4)
  return (
    <div className="gantt-scroll" ref={box}>
      <div className="gantt-box" style={{ width: W }}>
        <svg className="gantt" width={W} height={Hh} role="img" aria-label={'Campaign timeline of the top ' + top.length + ' drainers: bar from first evidence to last activity, dots are drains'}>
          {ticks.map((t, i) => (
            <g key={i}>
              <line className="gl" x1={xs(t)} x2={xs(t)} y1={T - 6} y2={Hh} />
              <text className="xt" x={xs(t)} y={T - 12} textAnchor={i === 4 ? 'end' : i === 0 ? 'start' : 'middle'}>{short ? fmtDay(t) + ' ' + fmtTime(t) : fmtDay(t)}</text>
            </g>
          ))}
          <line className="nowl" x1={xs(now)} x2={xs(now)} y1={T - 6} y2={Hh} />
          {top.map((r, i) => {
            const y = T + i * RH + RH / 2
            const x0 = xs(r.start), x1 = Math.max(x0 + 3, xs(r.last))
            const ds = r.c.drainList.filter(d => Number.isFinite(d.t) && d.t >= lo)
            return (
              <g key={r.c.key} className="grow" role="button" tabIndex={0} aria-label={'Open case ' + r.c.caseNo + ', ' + r.c.tier + ', ' + fmtUSD(r.usd)}
                style={css({ '--tc': tv(r.c.tier) })}
                onClick={() => onOpen(r.c)} onKeyDown={e => { if (e.key === 'Enter') onOpen(r.c) }}
                onMouseEnter={e => { const b = (e.currentTarget.ownerSVGElement as SVGSVGElement).getBoundingClientRect(); setHover({ r, x: Math.min(e.clientX - b.left, W - 220), y }) }}
                onMouseLeave={() => setHover(null)}>
                <rect className="hit" x={0} y={y - RH / 2} width={W} height={RH} />
                <line className="rl" x1={L} x2={W - R} y1={y + RH / 2} y2={y + RH / 2} />
                <text className="lab" x={L - 8} y={y} dy={4} textAnchor="end"><tspan className="tgt">{r.c.tier}</tspan> <tspan className="mono">{mid(r.c.address, 6, 4)}</tspan></text>
                <rect className="bar" x={x0} y={y - 5} width={x1 - x0} height={10} rx={2} />
                {ds.map(d => <circle key={d.tx + d.victim} className="dot" cx={xs(d.t)} cy={y} r={d.usd ? 2.6 + Math.min(3.4, Math.log10(1 + d.usd) * 0.8) : 2.2}><title>{fmtStamp(d.t)}: {d.usd == null ? 'unpriced ' + (d.symbol || '') : fmtUSD(d.usd)}</title></circle>)}
              </g>
            )
          })}
        </svg>
        {hover ? (
          <div className="chart-tip gantt-tip" style={{ left: hover.x + 12, top: hover.y + 14 }} role="status">
            <div className="chart-tip-label">{hover.r.c.tier} {hover.r.c.title}, {chainLong(hover.r.c.chain)}</div>
            <div className="chart-tip-row"><span className="chart-tip-name">Start</span><span className="chart-tip-val">{fmtStamp(hover.r.start)}</span></div>
            <div className="chart-tip-row"><span className="chart-tip-name">Last</span><span className="chart-tip-val">{fmtStamp(hover.r.last)}</span></div>
            <div className="chart-tip-row"><span className="chart-tip-name">Taken</span><span className="chart-tip-val">{fmtUSD(hover.r.usd)}</span></div>
            <div className="chart-tip-row"><span className="chart-tip-name">Drains</span><span className="chart-tip-val">{fmtInt(hover.r.drains)} ({hover.r.c.drainList.length} published)</span></div>
          </div>
        ) : null}
      </div>
    </div>
  )
}

const recConfig = { usd: { label: 'Received', color: 'var(--chart-3)' } } satisfies ChartConfig

function WhoReceives({ recs, onOpen }: { recs: Recipient[]; onOpen: (c: Case) => void }) {
  const data = useMemo(() => recs.filter(r => r.usd > 0).slice(0, TOP_RECIPIENTS)
    .map(r => ({ id: r.chain + ':' + r.wallet, usd: Math.round(r.usd), n: r.drainers.length, rec: r })), [recs])
  const ticks = useMemo(() => new Map(data.map(d => [d.id, { addr: d.rec.wallet, chain: d.rec.chain }])), [data])
  const list = recs.slice().sort((a, b) => b.drainers.length - a.drainers.length || b.usd - a.usd).slice(0, 8)
  if (!recs.length) return <p className="empty">No payout wallet or drain recipient is recorded for this selection.</p>
  const h = 30 + data.length * 28
  return (
    <div className="rec-two">
      {data.length ? (
        <ChartContainer config={recConfig} className="aspect-auto w-full" style={{ height: h }} initialDimension={{ width: 560, height: h }}>
          <BarChart accessibilityLayer data={data} layout="vertical" margin={{ top: 4, right: 92, left: 4, bottom: 4 }}>
            <CartesianGrid horizontal={false} strokeDasharray="2 4" />
            <XAxis type="number" dataKey="usd" tickFormatter={v => fmtUSD(v, true)} tickLine={false} axisLine={{ stroke: 'var(--border)' }} tickCount={4} />
            <YAxis type="category" dataKey="id" width={128} tickLine={false} axisLine={false} interval={0} tick={<AddrTick rows={ticks} />} />
            <ChartTooltip cursor={{ fill: 'var(--muted)' }} content={<ChartTooltipContent hideIndicator
              labelFormatter={(_, p) => { const r = (p?.[0]?.payload as { rec: Recipient })?.rec; return r ? r.roles.map(x => roleInfo(x)[0]).join(', ') + ' on ' + chainLong(r.chain) : '' }}
              formatter={(v, _n, item) => { const r = (item.payload as { rec: Recipient }).rec; return (
                <span className="flex w-full flex-col gap-0.5"><span className="flex justify-between gap-3"><span className="muted">Received</span><b className="num">{fmtUSD(Number(v))}</b></span><span className="flex justify-between gap-3"><span className="muted">Fed by</span><b className="num">{plural(r.drainers.length, 'drainer')}</b></span><span className="mono" style={{ fontSize: 11 }}>{r.wallet}</span>{r.basis === 'window' ? <span className="muted">from the published drains only</span> : null}</span>
              ) }} />} />
            <Bar dataKey="usd" radius={[0, 2, 2, 0]} isAnimationActive={false}>
              {data.map(d => <Cell key={d.id} fill={d.n >= 2 ? 'var(--t1)' : 'var(--chart-3)'} />)}
              <LabelList dataKey="n" position="right" className="barlabel" formatter={(v: unknown) => plural(Number(v), 'drainer')} />
            </Bar>
          </BarChart>
        </ChartContainer>
      ) : <p className="empty">None of these wallets has a priced amount yet; they are listed below by the number of drainers feeding them.</p>}
      <ul className="links reclist">
        {list.map(r => (
          <li key={r.chain + r.wallet}>
            <Addr value={r.wallet} chain={r.chain} h={8} t={6} link />
            <span className="muted small">{r.roles.map(x => roleInfo(x)[0].toLowerCase()).join(', ')}, {chainShort(r.chain)}</span>
            <span className={'small' + (r.drainers.length >= 2 ? ' shared' : '')}>fed by {r.drainers.length >= 2 ? <b>{r.drainers.length} drainers</b> : '1 drainer'}:</span>
            {r.drainers.slice(0, 3).map(c => <button key={c.key} className="linkbtn small mono" onClick={() => onOpen(c)}>{mid(c.address, 6, 4)}</button>)}
            {r.drainers.length > 3 ? <span className="muted small">+{r.drainers.length - 3}</span> : null}
            <span className="num small rgt">{r.usd ? fmtUSD(r.usd) : <span className="muted">unpriced</span>}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function PerChain({ rows }: { rows: DrainerRow[] }) {
  const s = useMemo(() => perChainSeries(rows), [rows])
  const config = useMemo(() => Object.fromEntries(s.chains.map((c, i) => [c, { label: chainLong(c), color: chainColor(c, i) }])) as ChartConfig, [s])
  if (!s.rows.length) return <p className="empty">None of these drainers has a drain in the latest published list.</p>
  if (!s.total) return <p className="empty">The published drains of these drainers are all unpriced, so there is no value to chart.</p>
  const fmtX = (v: number) => (s.bucket === 'day' ? fmtDay(v) : fmtTime(v))
  return (
    <>
      <ChartContainer config={config} className="aspect-auto h-[200px] w-full" initialDimension={{ width: 460, height: 200 }}>
        <AreaChart accessibilityLayer data={s.rows} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
          <CartesianGrid vertical={false} strokeDasharray="2 4" />
          <XAxis dataKey="t" tickFormatter={fmtX} tickLine={false} axisLine={{ stroke: 'var(--border)' }} minTickGap={28} />
          <YAxis tickFormatter={v => fmtUSD(v, true)} tickLine={false} axisLine={false} width={50} tickCount={4} />
          <ChartTooltip content={<ChartTooltipContent indicator="dot" labelFormatter={(_, p) => { const t = (p?.[0]?.payload as { t: number })?.t; return s.bucket !== 'day' ? fmtDay(t) + ', ' + fmtTime(t) + ' UTC' : fmtDay(t) }}
            formatter={(v, name, item) => (
              <span className="flex w-full items-center justify-between gap-3"><span className="flex items-center gap-1.5"><i className="h-2.5 w-2.5 rounded-[2px]" style={{ background: item.color }} /><span className="muted">{chainLong(String(name))}</span></span><b className="num">{fmtUSD(Number(v))}</b></span>
            )} />} />
          {s.chains.map(c => <Area key={c} dataKey={c} type="monotone" stackId="a" stroke={'var(--color-' + c + ')'} fill={'var(--color-' + c + ')'} fillOpacity={0.35} strokeWidth={1.5} isAnimationActive={false} />)}
        </AreaChart>
      </ChartContainer>
      <div className="legend small chain-legend">{s.chains.map((c, i) => <span key={c}><i style={{ background: chainColor(c, i) }} />{chainLong(c)}</span>)}</div>
    </>
  )
}

/* ---------------- page ---------------- */

function download(name: string, text: string) {
  try {
    const url = URL.createObjectURL(new Blob(['﻿' + text], { type: 'text/csv;charset=utf-8' }))
    const a = document.createElement('a')
    a.href = url
    a.download = name
    document.body.appendChild(a)
    a.click()
    a.remove()
    setTimeout(() => URL.revokeObjectURL(url), 1000)
  } catch { /* download unavailable */ }
}

export default function Analytics({ model, onOpen }: { model: Model; onOpen: (c: Case) => void }) {
  const [f, setF] = useState<Filter>(DEFAULT_FILTER)
  const small = useMedia('(max-width: 640px)')
  const rows = useMemo(() => drainerRows(model, f), [model, f])
  const recs = useMemo(() => recipients(model, rows), [model, rows])
  const chains = useMemo(() => [...new Set([...model.chains.map(c => c[0]), ...model.cases.map(c => c.chain)])], [model])
  const dw = drainWindow(model)
  const capped = dw.n >= 500
  const toggleTier = (t: Tier) => setF(x => {
    const tiers = x.tiers.includes(t) ? x.tiers.filter(y => y !== t) : TIER_ORDER.filter(y => y === t || x.tiers.includes(y))
    return { ...x, tiers: tiers.length ? tiers : [t] }
  })
  const w = windowOf(f.window)
  const csv = () => download('drainers-' + f.window + '-' + (f.chain === 'all' ? 'all-chains' : f.chain) + '-' + model.data.generated_at.slice(0, 10) + '.csv', toCSV(rows))
  const windowNote = <>Drain-level details come from the latest {fmtInt(dw.n)} published drains{Number.isFinite(dw.from) ? <>, {fmtStamp(dw.from)} to {fmtStamp(dw.to)}</> : null}{capped ? '; older drains are not in data.json' : ''}.</>

  return (
    <div className="analytics">
      <section className="sect" id="active">
        <SummaryStrip model={model} rows={rows} f={f} recs={recs} />
      </section>
      <FreezableNow model={model} onOpen={onOpen} />
      <AtRiskNow model={model} onOpen={onOpen} />
      <section className="sect" id="active-table">
        <div className="sect-h"><h2>Drainers active now</h2><p>Ranked by value taken since each campaign began. Select a row to open its file.</p></div>
        <div className="card card-pad ruled ranked">
          <div className="filters an-filters" role="group" aria-label="Filter drainers">
            <span className="fl">Tier</span>
            {TIER_ORDER.map(t => <button key={t} className="chipf" aria-pressed={f.tiers.includes(t)} onClick={() => toggleTier(t)} style={css({ '--tc': tv(t) })}>{t} {TIER_NAME[t].toLowerCase()}</button>)}
            <span className="fl">Chain</span>
            {['all', ...chains].map(ch => <button key={ch} className="chipf" aria-pressed={f.chain === ch} onClick={() => setF(x => ({ ...x, chain: ch }))}>{ch === 'all' ? 'All' : chainShort(ch)}</button>)}
            <span className="fl">Active in</span>
            {WINDOWS.map(x => <button key={x.key} className="chipf" aria-pressed={f.window === x.key} onClick={() => setF(y => ({ ...y, window: x.key }))}>{small && x.key !== 'all' ? x.key : x.label}</button>)}
            <button className="btn csv" onClick={csv} disabled={!rows.length}>Export CSV</button>
          </div>
          {rows.length ? <RankTable model={model} rows={rows} onOpen={onOpen} /> : (
            <p className="empty">No {tierPhrase(f.tiers)} drainer was active{f.chain === 'all' ? '' : ' on ' + chainLong(f.chain)} {w.phrase}.
              {f.window !== 'all' ? <> <button className="linkbtn" onClick={() => setF(x => ({ ...x, window: 'all' }))}>Show all time</button>.</> : null}
              {f.tiers.length < 3 ? <> <button className="linkbtn" onClick={() => setF(x => ({ ...x, tiers: [...TIER_ORDER] }))}>Include every tier</button>.</> : null}</p>
          )}
          <p className="note-row"><span>Taken, victims and drains cover each drainer's whole history; unpriced tokens count as zero. Campaign start is the first evidence or drain we recorded. {windowNote} Recipients are payout wallets with the role inferred from share size.</span></p>
        </div>
      </section>

      <section className="sect" id="charts">
        <div className="sect-h"><h2>Where the campaigns stand</h2><p>The same selection as the table: {plural(rows.length, 'drainer')}, {tierPhrase(f.tiers)}, {f.chain === 'all' ? 'every chain' : chainLong(f.chain)}, active {w.phrase}.</p></div>
        <div className="an-grid">
          <div className="card card-pad chartcard">
            <h3>Top drainers by value taken</h3>
            <p className="cap">Top {TOP_BARS} by USD; bar colour is the tier. Select a bar to open the file.</p>
            <TopDrainers rows={rows} onOpen={onOpen} />
            <div className="legend small">{TIER_ORDER.filter(t => f.tiers.includes(t)).map(t => <span key={t}><i style={{ background: tv(t) }} />{t} {TIER_NAME[t].toLowerCase()}</span>)}</div>
          </div>
          <div className="card card-pad chartcard">
            <h3>Value taken over time, by chain</h3>
            <p className="cap">Stacked USD per {perChainSeries(rows).bucket} from the published drains of these drainers.</p>
            <PerChain rows={rows} />
            <p className="cap">{windowNote}</p>
          </div>
          <div className="card card-pad chartcard wide">
            <h3>Campaign timeline</h3>
            <p className="cap">Top {TOP_GANTT} by value. The bar runs from the campaign start to the last activity; dots are drains (larger is more value); the dashed line is the time of this report.</p>
            <Gantt rows={rows} now={model.now} onOpen={onOpen} />
            <p className="cap">Dots exist only for drains in the latest published list{Number.isFinite(dw.from) ? ', since ' + fmtStamp(dw.from) : ''}; earlier drains of a long campaign are not drawn.</p>
          </div>
          <div className="card card-pad chartcard wide">
            <h3>Who receives the money</h3>
            <p className="cap">Payout wallets and drain recipients, summed across drainers. Red bars are fed by two or more drainers: a shared collector usually means one operator.</p>
            <WhoReceives recs={recs} onOpen={onOpen} />
            <p className="cap">Received is every drain sent to the wallet (all tracked drainers, full history) where we have it, otherwise the published drains only.</p>
          </div>
        </div>
      </section>
    </div>
  )
}
