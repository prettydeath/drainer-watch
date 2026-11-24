import { useEffect, useMemo, useRef, useState } from 'react'
import { animate, createScope, scrambleText, stagger } from 'animejs'
import { Dialog as DialogPrimitive } from 'radix-ui'
import { CartesianGrid, Line, LineChart, XAxis, YAxis } from 'recharts'
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from '@/components/ui/chart'
import { DAY, H, fmtDay, fmtStamp, fmtTime, fmtUSD, plural } from '@/lib/format'
import type { Case, Model } from '@/lib/model'
import { walletFile, type WalletFile } from '@/lib/wallet'
import { TIER_NAME, chainLong, chainShort, kindText, labelInfo, roleInfo } from '@/lib/vocab'
import { Addr, FullId, Tx, reduceMotion, tv } from './shared'

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const cfg = {
  cum: { label: 'Received so far', color: 'var(--tc)' },
  n: { label: 'Drains in the period', color: 'var(--chart-2)' },
} satisfies ChartConfig

function Inflows({ w, now }: { w: WalletFile; now: number }) {
  const rows = useMemo(() => {
    const ts = w.inflows.map(i => i.t).filter(Number.isFinite)
    if (!ts.length) return { data: [], size: DAY }
    const lo = Math.min(...ts), hi = Math.max(now, ...ts)
    const size = hi - lo <= 3 * DAY ? H : DAY
    const first = Math.floor(lo / size) * size, last = Math.floor(hi / size) * size
    const m = new Map<number, { usd: number; n: number }>()
    w.inflows.forEach(i => {
      if (!Number.isFinite(i.t)) return
      const k = Math.floor(i.t / size) * size
      const x = m.get(k) || { usd: 0, n: 0 }
      x.usd += i.usd || 0
      x.n++
      m.set(k, x)
    })
    let cum = 0
    const data: { t: number; cum: number; n: number }[] = []
    for (let t = first; t <= last && data.length < 400; t += size) {
      const x = m.get(t) || { usd: 0, n: 0 }
      cum += x.usd
      data.push({ t, cum: Math.round(cum), n: x.n })
    }
    data.unshift({ t: first - size, cum: 0, n: 0 })          // start from zero before the first inflow
    return { data, size }
  }, [w, now])
  if (!rows.data.length) return <p className="muted">No inflow from a drain is on record for this wallet{w.full ? '' : ' in the latest published drains'}.</p>
  const fx = (v: number) => (rows.size === H ? fmtTime(v) : fmtDay(v))
  return (
    <>
      <ChartContainer config={cfg} className="aspect-auto h-[190px] w-full" style={{ marginLeft: -6 }} initialDimension={{ width: 460, height: 190 }}>
        <LineChart accessibilityLayer data={rows.data} margin={{ top: 10, right: 8, left: 0, bottom: 0 }}>
          <CartesianGrid vertical={false} strokeDasharray="2 4" />
          <XAxis dataKey="t" tickFormatter={fx} tickLine={false} axisLine={{ stroke: 'var(--border)' }} minTickGap={28} />
          <YAxis yAxisId="u" tickFormatter={v => fmtUSD(v, true)} tickLine={false} axisLine={false} width={52} tickCount={4} />
          <YAxis yAxisId="n" orientation="right" tickLine={false} axisLine={false} width={26} allowDecimals={false} tickCount={4} />
          <ChartTooltip content={<ChartTooltipContent labelFormatter={(_, p) => { const t = (p?.[0]?.payload as { t: number })?.t; return rows.size === H ? fmtDay(t) + ', ' + fmtTime(t) + ' UTC' : fmtDay(t) }}
            formatter={(v, name) => (
              <span className="flex w-full justify-between gap-3"><span className="muted">{name === 'cum' ? 'Received so far' : 'Drains in the period'}</span><b className="num">{name === 'cum' ? fmtUSD(Number(v)) : String(v)}</b></span>
            )} />} />
          <Line yAxisId="u" dataKey="cum" type="stepAfter" stroke="var(--color-cum)" strokeWidth={2} dot={false} isAnimationActive={false} />
          <Line yAxisId="n" dataKey="n" type="monotone" stroke="var(--color-n)" strokeWidth={1} strokeDasharray="3 3" dot={{ r: 2.5, fill: 'var(--color-n)', strokeWidth: 0 }} isAnimationActive={false} />
        </LineChart>
      </ChartContainer>
      <div className="meta">Solid line: drain money received so far; dotted: drains per {rows.size === H ? 'hour' : 'day'}, right scale.{w.full ? (w.nIn > w.inflows.length ? ' Drawn from the latest ' + w.inflows.length + ' of ' + w.nIn + ' inflows.' : '') : ' Drawn from the latest published drains only.'}</div>
    </>
  )
}

export default function WalletSpread({ chain, address, model, onClose, onOpen }: {
  chain: string; address: string; model: Model; onClose: () => void; onOpen: (c: Case) => void
}) {
  const ref = useRef<HTMLDivElement>(null)
  const [copied, setCopied] = useState(false)
  const w = useMemo(() => walletFile(model, chain, address), [model, chain, address])
  useEffect(() => {
    document.documentElement.classList.add('has-open')
    return () => document.documentElement.classList.remove('has-open')
  }, [])
  useEffect(() => {
    const root = ref.current
    if (!root) return
    const scroller = root.closest('.scrim')
    if (scroller) scroller.scrollTop = 0
    if (reduceMotion()) return
    const scope = createScope({ root: root as unknown as HTMLElement }).add(() => {
      animate(root.querySelector('.page.left')!, { opacity: [0, 1], rotateY: [8, 0], duration: 420, ease: 'out(3)' })
      animate(root.querySelector('.page.right')!, { opacity: [0, 1], rotateY: [-8, 0], duration: 420, ease: 'out(3)', delay: 70 })
      const ids = root.querySelectorAll('.subjects .full[data-full]')
      if (ids.length)
        animate(ids, {
          innerHTML: scrambleText({ chars: chain === 'tron' ? B58 : '0-9a-f', revealRate: 110, settleDuration: 260, from: 'left' } as never),
          delay: stagger(60, { start: 260 }),
        })
    })
    return () => scope.revert()
  }, [w, chain])

  const roleName = w.roles.length ? roleInfo(w.roles[0])[0] : 'Linked'
  const strong = w.drainers.filter(d => (d.c?.tier || d.tier) && (d.c?.tier || d.tier) !== 'T3')
  const traceable = w.holdings.filter(r => !r.f.already_frozen).reduce((s, r) => s + r.traceable, 0)
  const held = w.holdings.filter(r => !r.f.already_frozen).reduce((s, r) => s + (r.f.usd || 0), 0)
  const deposits = [...new Map(w.outflows.filter(o => o.kind === 'deposit_sweep').map(o => [o.counterparty, o])).values()]
  const copyLink = () => {
    try { navigator.clipboard?.writeText(location.href).catch(() => {}) } catch { /* unavailable */ }
    setCopied(true)
    setTimeout(() => setCopied(false), 1400)
  }
  const ev = (c: Case | null) => (c ? [...new Set([...c.labels, ...c.evidence.map(e => e.type)])].map(l => labelInfo(l)[0]) : [])

  return (
    <DialogPrimitive.Root open onOpenChange={o => { if (!o) onClose() }}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="scrim">
          <DialogPrimitive.Content ref={ref} className="spread" aria-describedby={undefined} style={{ '--tc': tv(w.bestTier) } as React.CSSProperties} data-wallet={w.key}>
            <DialogPrimitive.Close className="closex" aria-label="Close file">✕</DialogPrimitive.Close>
            <section className="page left">
              <div className="meta">Wallet file DW-W-{chainShort(chain).toUpperCase().slice(0, 3)}-{w.address.slice(-4).toUpperCase()}{Number.isFinite(w.firstIn) ? ', first drain money ' + fmtStamp(w.firstIn) : ''}</div>
              <DialogPrimitive.Title asChild><h2>{roleName} wallet on {chainLong(chain)}</h2></DialogPrimitive.Title>
              <div className="verdict">
                {w.bestTier ? <span className="big">linked to {w.bestTier} {TIER_NAME[w.bestTier].toLowerCase()}</span> : <span className="big">no tracked drainer</span>}
                <span className="meta">{w.roles.length ? w.roles.map(r => roleInfo(r)[0].toLowerCase()).join(', ') : 'role not recorded'}</span>
              </div>
              {w.known ? (
                <p>
                  {w.drainers.length ? <>Receives money for {plural(w.drainers.length, 'tracked drainer')}{strong.length ? <> ({strong.length} confirmed or strong)</> : null}. </> : null}
                  {w.nIn ? <>It received <b>{fmtUSD(w.totalIn)}</b> in {plural(w.nIn, 'drain')}{Number.isFinite(w.firstIn) ? <> between {fmtDay(w.firstIn)} and {fmtDay(w.lastIn)}</> : null}{w.full ? '' : ' (latest published drains only)'}. </> : <>No drain money sent straight to it is on record{w.full ? '' : ' in the latest published drains'}. </>}
                  {w.clusters.filter(c => c.shared).map(c => <span key={c.cluster}>Shared payout wallet of operator cluster <span className="mono small">{c.cluster}</span> ({plural(c.members, 'drainer')}). </span>)}
                  <span className="muted">Payout roles are inferred from share size; a wallet can also hold money from other, possibly legitimate, sources.</span>
                </p>
              ) : <p className="muted">This wallet has no record in the current data: it is not a payout wallet, recipient or holder of any tracked drainer.</p>}

              <h4>Holdings that can be frozen</h4>
              {!model.freezable ? <p className="muted">Not computed yet for this data.</p> : w.holdings.length ? (
                <>
                  <ul className="links">{w.holdings.map((r, i) => (
                    <li key={i}>
                      <b>{r.f.usd == null ? 'unpriced' : fmtUSD(r.f.usd)}</b> <span>{r.f.symbol}</span><span className="muted small">{r.f.issuer || ''}</span>
                      {r.f.already_frozen ? <span className="badge-frozen">already frozen</span> : <span className="muted small">not frozen</span>}
                      {r.f.checked_at ? <span className="muted small">checked {fmtStamp(r.f.checked_at)}</span> : null}
                    </li>
                  ))}</ul>
                  {held > 0 ? (
                    <p className="meta">Traceable to drains: <b>{fmtUSD(traceable)}</b> of {fmtUSD(held)}. Traceable is the part of the balance its linked drainer is known to have taken; {held > traceable ? <><b>{fmtUSD(held - traceable)}</b> is not traced to drains and may come from elsewhere. Verify before requesting a freeze.</> : 'the whole balance is covered.'}</p>
                  ) : null}
                </>
              ) : <p className="muted">No freezable stablecoin balance at the last check.</p>}

              <h4>Timeline</h4>
              <Inflows w={w} now={model.now} />

              <h4>Linked drainers</h4>
              {w.drainers.length ? (
                <div className="rank-wrap">
                  <table className="ledger wl-drainers">
                    <thead><tr><th>Drainer</th><th>Role</th><th className="r">Sent here</th><th className="r">First, last</th></tr></thead>
                    <tbody>{w.drainers.map(d => {
                      const t = d.c?.tier || d.tier
                      return (
                        <tr key={d.drainer} className={d.c ? 'row' : ''} style={{ '--tc': tv(t) } as React.CSSProperties} onClick={() => d.c && onOpen(d.c)} tabIndex={d.c ? 0 : undefined} onKeyDown={e => { if (e.key === 'Enter' && d.c) onOpen(d.c) }}>
                          <td>{t ? <span className="tg">{t}</span> : null} <Addr value={d.drainer} chain={chain} link /><span className="sub ev">{ev(d.c).slice(0, 2).join(', ')}</span></td>
                          <td>{d.role ? roleInfo(d.role)[0].toLowerCase() : <span className="muted">recipient</span>}{d.share ? ' ' + Math.round(d.share * 100) + '%' : ''}</td>
                          <td className="r">{d.usd ? fmtUSD(d.usd) : <span className="muted">$0</span>}<span className="sub">{plural(d.txs, 'drain')}</span></td>
                          <td className="r small">{d.first ? fmtDay(d.first) : <span className="muted">n/a</span>}{d.last && d.last !== d.first ? <span className="sub">{fmtDay(d.last)}</span> : null}</td>
                        </tr>
                      )
                    })}</tbody>
                  </table>
                </div>
              ) : <p className="muted">No tracked drainer pays this wallet.</p>}

              <h4>Subjects</h4>
              <ul className="subjects">
                <li><span>Wallet</span><FullId value={w.address} chain={chain} /></li>
                {w.drainers.slice(0, 6).map(d => <li key={d.drainer}><span>Drainer {d.c?.tier || d.tier || ''}</span><FullId value={d.drainer} chain={chain} /></li>)}
                {deposits.slice(0, 4).map(o => <li key={o.counterparty}><span>{(o.entity || 'Exchange') + ' deposit'}</span><FullId value={o.counterparty} chain={chain} /></li>)}
              </ul>
            </section>

            <section className="page right">
              <h4 style={{ marginTop: 0 }}>Inflows from drains</h4>
              {w.inflows.length ? (
                <ol className="exhibits">{w.inflows.map((i, k) => (
                  <li key={i.tx + k}>
                    <b>{i.usd == null ? 'Unpriced ' + (i.symbol || 'tokens') : fmtUSD(i.usd) + ' ' + (i.symbol || '')}</b>, {fmtStamp(i.ts)}. <Tx chain={chain} tx={i.tx}>Transaction</Tx>
                    <p>From victim <Addr value={i.victim} chain={chain} link /> through drainer <Addr value={i.drainer} chain={chain} link />{i.amount ? <>, amount {i.amount} {i.symbol || ''}</> : null}.</p>
                  </li>
                ))}</ol>
              ) : <p className="muted">None on record{w.full ? '' : ' in the latest published drains'}.</p>}
              {w.full && w.nIn > w.inflows.length ? <p className="meta">The latest {w.inflows.length} of {w.nIn} inflows are listed; totals count all of them.</p> : null}
              {!w.full ? <p className="meta">Inflow history is limited to the latest published drains: this data.json has no wallet aggregate.</p> : null}

              <h4>Outflows we know of</h4>
              {w.outflows.length ? (
                <ol className="exhibits" style={{ '--start': w.inflows.length } as React.CSSProperties}>{w.outflows.map((o, k) => (
                  <li key={(o.tx || '') + k}>
                    <b>{o.entity || 'An exchange'}</b> received {o.usd != null ? fmtUSD(o.usd) : 'an unpriced amount' + (o.symbol ? ' of ' + o.symbol : '')}{o.ts ? ', ' + fmtStamp(o.ts) : ''}. <Tx chain={chain} tx={o.tx}>Transaction</Tx>
                    <p>{kindText(o.kind)}{o.confidence ? ', ' + o.confidence + ' confidence' : ''}; to <Addr value={o.counterparty} chain={chain} link />.</p>
                  </li>
                ))}</ol>
              ) : <p className="muted">No outflow to an exchange seen yet. Other outgoing transfers are not followed.</p>}

              <h4>Where the money went next</h4>
              {w.outflows.length ? (
                <ul className="links">{[...new Map(w.outflows.map(o => [o.entity || 'Unnamed exchange', o])).keys()].map(e => {
                  const os = w.outflows.filter(o => (o.entity || 'Unnamed exchange') === e)
                  return <li key={e}><b>{e}</b><span className="muted small">{plural(os.length, 'transfer')}, {fmtUSD(os.reduce((s, o) => s + (o.usd || 0), 0))}</span></li>
                })}</ul>
              ) : <p className="muted">Not traced beyond this wallet.</p>}

              <div className="spread-tools">
                <button className="btn" onClick={() => window.print()}>Print this file</button>
                <button className="btn" onClick={copyLink}>{copied ? 'Link copied' : 'Copy link to this file'}</button>
              </div>
            </section>
          </DialogPrimitive.Content>
        </DialogPrimitive.Overlay>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  )
}
