import { useEffect, useMemo, useRef, useState } from 'react'
import { animate, createScope, scrambleText, stagger } from 'animejs'
import { Dialog as DialogPrimitive } from 'radix-ui'
import { CartesianGrid, Line, LineChart, XAxis, YAxis } from 'recharts'
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from '@/components/ui/chart'
import { DAY, fmtDay, fmtStamp, fmtTime, fmtUSD, plural } from '@/lib/format'
import type { Case, Model } from '@/lib/model'
import { TIERS, TIER_NAME, chainLong, chainShort, famSourceNote, kindText, labelInfo, roleInfo, viaText } from '@/lib/vocab'
import { Addr, FullId, Tx, reduceMotion, tv } from './shared'

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
const MAX_TIMELINE_DAYS = 90

const timelineConfig = {
  cum: { label: 'Taken so far', color: 'var(--tc)' },
  n: { label: 'Drains that day', color: 'var(--chart-2)' },
} satisfies ChartConfig

function Timeline({ c, now }: { c: Case; now: number }) {
  const rows = useMemo(() => {
    const ts = c.drainList.map(d => d.t).filter(Number.isFinite)
    if (!ts.length) return []
    const lastDay = Math.floor(Math.max(now, ...ts) / DAY) * DAY
    const firstDay = Math.max(Math.floor(Math.min(...ts) / DAY) * DAY, lastDay - (MAX_TIMELINE_DAYS - 1) * DAY)
    const m = new Map<number, { usd: number; n: number }>()
    c.drainList.forEach(d => {
      const k = Math.floor(d.t / DAY) * DAY
      const x = m.get(k) || { usd: 0, n: 0 }
      x.usd += d.usd || 0
      x.n++
      m.set(k, x)
    })
    let cum = 0
    const out: { t: number; cum: number; n: number }[] = []
    for (let t = firstDay; t <= lastDay; t += DAY) {
      const x = m.get(t) || { usd: 0, n: 0 }
      cum += x.usd
      out.push({ t, cum: Math.round(cum), n: x.n })
    }
    if (out.length === 1) out.unshift({ t: firstDay - DAY, cum: 0, n: 0 })
    return out
  }, [c, now])
  if (!rows.length) return <p className="muted">None of its drains is in the latest published drain list, so there is no timeline to draw.</p>
  return (
    <>
      <ChartContainer config={timelineConfig} className="aspect-auto h-[200px] w-full" style={{ marginLeft: -6 }} initialDimension={{ width: 460, height: 200 }}>
        <LineChart accessibilityLayer data={rows} margin={{ top: 10, right: 8, left: 0, bottom: 0 }}>
          <CartesianGrid vertical={false} strokeDasharray="2 4" />
          <XAxis dataKey="t" tickFormatter={v => fmtDay(v)} tickLine={false} axisLine={{ stroke: 'var(--border)' }} minTickGap={28} />
          <YAxis yAxisId="u" tickFormatter={v => fmtUSD(v, true)} tickLine={false} axisLine={false} width={52} tickCount={4} />
          <YAxis yAxisId="n" orientation="right" tickLine={false} axisLine={false} width={26} allowDecimals={false} tickCount={4} />
          <ChartTooltip content={<ChartTooltipContent labelFormatter={(_, p) => fmtDay((p?.[0]?.payload as { t: number })?.t)}
            formatter={(v, name) => (
              <span className="flex w-full justify-between gap-3"><span className="muted">{name === 'cum' ? 'Taken so far' : 'Drains that day'}</span><b className="num">{name === 'cum' ? fmtUSD(Number(v)) : String(v)}</b></span>
            )} />} />
          <Line yAxisId="u" dataKey="cum" type="stepAfter" stroke="var(--color-cum)" strokeWidth={2} dot={false} isAnimationActive={false} />
          <Line yAxisId="n" dataKey="n" type="monotone" stroke="var(--color-n)" strokeWidth={1} strokeDasharray="3 3" dot={{ r: 2.5, fill: 'var(--color-n)', strokeWidth: 0 }} isAnimationActive={false} />
        </LineChart>
      </ChartContainer>
      <div className="meta">Solid line: value taken so far. Dotted: drains per day, right scale. Drawn from the latest published drains{rows.length >= MAX_TIMELINE_DAYS ? ', last 90 days' : ''}.</div>
    </>
  )
}

function Freeze({ c, model }: { c: Case; model: Model }) {
  if (!model.freezable) return <p className="muted">Not computed yet for this data.</p>
  const g = model.freezeByCase.get(c.key)
  if (!g || !g.rows.length) return <p className="muted">No freezable stablecoin balance found on its linked wallets at the last check.</p>
  return (
    <ul className="links">
      {g.rows.map((f, i) => (
        <li key={i}>
          <Addr value={f.address} chain={f.chain} link />
          <span className="muted small">{roleInfo(f.role)[0].toLowerCase()}</span>
          <span>{f.usd == null ? <span className="muted">unpriced</span> : fmtUSD(f.usd)} {f.symbol || ''}{f.issuer ? <span className="muted small"> ({f.issuer})</span> : null}</span>
          {f.already_frozen ? <span className="badge-frozen">already frozen</span> : null}
          {f.checked_at ? <span className="muted small">checked {fmtStamp(f.checked_at)}</span> : null}
        </li>
      ))}
    </ul>
  )
}

function Deployer({ c }: { c: Case }) {
  const d = c.deployer
  if (c.isWallet === true)
    return <p>This subject is a wallet (an externally owned account), not a contract: it has no code, so nobody deployed it.{d.funder ? <> It was funded by <Addr value={d.funder} chain={c.chain} link />{d.funder_entity ? <> ({d.funder_entity})</> : null}.</> : null}</p>
  if (d.address)
    return (
      <p>
        Deployed by <Addr value={d.address} chain={c.chain} link />{d.tx ? <> in <Tx chain={c.chain} tx={d.tx} /></> : null}
        {d.factory ? <> through factory <Addr value={d.factory} chain={c.chain} link /></> : null}
        {d.block ? <> at block {d.block.toLocaleString('en-US')}</> : null}.
        {d.funder ? <> The deployer was funded by <Addr value={d.funder} chain={c.chain} link />{d.funder_entity ? <> ({d.funder_entity})</> : null}{d.funder_tx ? <>, <Tx chain={c.chain} tx={d.funder_tx}>transaction</Tx></> : null}.</> : d.funder_entity ? <> Funded from {d.funder_entity}.</> : null}
        {' '}It has {plural(d.other_contracts, 'other flagged contract')}. <span className="muted small">Source: {viaText(d.via)}.</span>
      </p>
    )
  return (
    <p>
      {c.isWallet === null
        ? 'We have not looked up whether this address holds code, and no creation transaction is visible to us; we do not guess.'
        : 'The creation transaction is not visible to us, and we do not guess.'}{' '}
      <span className="muted small">Lookup: {viaText(d.via)}.</span>
    </p>
  )
}

export default function CaseSpread({ c, model, onClose, onOpen }: { c: Case; model: Model; onClose: () => void; onOpen: (c: Case) => void }) {
  const ref = useRef<HTMLDivElement>(null)
  const [linkCopied, setLinkCopied] = useState(false)
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
      // page turn: the two pages swing in from the spine
      animate(root.querySelector('.page.left')!, { opacity: [0, 1], rotateY: [8, 0], duration: 420, ease: 'out(3)' })
      animate(root.querySelector('.page.right')!, { opacity: [0, 1], rotateY: [-8, 0], duration: 420, ease: 'out(3)', delay: 70 })
      const ids = root.querySelectorAll('.subjects .full[data-full]')
      if (ids.length)
        animate(ids, {
          innerHTML: scrambleText({ chars: c.chain === 'tron' ? B58 : '0-9a-f', revealRate: 110, settleDuration: 260, from: 'left' } as never),
          delay: stagger(60, { start: 260 }),
        })
    })
    return () => scope.revert()
  }, [c])

  const self: [string, string] = [c.isWallet ? 'Wallet' : c.isWallet === false ? 'Contract' : 'Address', c.address]
  const subj: [string, string | null][] = [
    self,
    ...(c.isWallet ? [] : [['Deployer', c.deployer.address] as [string, string | null]]),
    ...c.payouts.map(p => [roleInfo(p.role)[0] + (p.share ? ' ' + Math.round(p.share * 100) + '%' : ''), p.wallet] as [string, string]),
    ...[...new Set(c.vasp_links.filter(v => v.kind === 'deposit_sweep').map(v => (v.entity || 'Exchange') + '|' + v.counterparty))]
      .map(s => [s.split('|')[0] + ' deposit', s.split('|')[1]] as [string, string]),
  ]
  const reached = c.vasp_links.filter(v => v.role !== 'deployer')
  const cl = c.cluster ? model.data.clusters.find(x => x.cluster === c.cluster) : null
  const mates = cl ? cl.members.filter(a => a !== c.address).map(a => model.byKey.get(cl.chain + ':' + a)).filter((x): x is Case => !!x) : []
  const twins = (c.cross_chain || []).map(x => model.byKey.get(x.chain + ':' + c.address)).filter((x): x is Case => !!x)
  const recent = c.drainList.slice(0, 8)
  const what = c.isWallet ? 'wallet' : c.isWallet === false ? 'contract' : 'address'
  const copyLink = () => {
    try { navigator.clipboard?.writeText(location.href).catch(() => {}) } catch { /* unavailable */ }
    setLinkCopied(true)
    setTimeout(() => setLinkCopied(false), 1400)
  }

  return (
    <DialogPrimitive.Root open onOpenChange={o => { if (!o) onClose() }}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="scrim">
          <DialogPrimitive.Content ref={ref} className="spread" aria-describedby={undefined} style={{ '--tc': tv(c.tier) } as React.CSSProperties} data-case={c.key}>
            <DialogPrimitive.Close className="closex" aria-label="Close file">✕</DialogPrimitive.Close>
            <section className="page left">
              <div className="meta">Case {c.caseNo}, opened {fmtStamp(c.first_seen)}</div>
              <DialogPrimitive.Title asChild><h2>{c.title} on {chainLong(c.chain)}</h2></DialogPrimitive.Title>
              <div className="verdict">
                <span className="big">{c.tier} {TIER_NAME[c.tier].toLowerCase()}</span>
                <span className="meta">score {c.score} of 100{c.source && c.source !== 'detector' ? ', listed by ' + c.source : ''}</span>
              </div>
              <p>
                {c.victims ? <>{plural(c.victims, 'wallet')} lost {c.usd ? fmtUSD(c.usd) : 'tokens we could not price'} to this {what} between {fmtDay(c.first_seen)} and {fmtDay(c.last_seen)}. </> : <>No victim is counted for this {what} yet; first seen {fmtDay(c.first_seen)}, last seen {fmtDay(c.last_seen)}. </>}
                {TIERS[c.tier] ? <span className="muted">{TIER_NAME[c.tier]}: {TIERS[c.tier][1]}</span> : null}
              </p>
              {c.family ? <p className="meta">Family {c.famLabel}{c.famSource ? ' (' + famSourceNote(c.famSource) + ')' : ''}, code hash <span className="mono">{c.family}</span>.</p> : null}
              {c.contract_name || c.verified != null ? (
                <p className="meta">{c.verified ? 'Verified source on the explorer' : c.verified === false ? 'Source not verified on the explorer' : ''}{c.contract_name ? (c.verified != null ? ', ' : '') + 'contract name ' + c.contract_name : ''}{c.code_size ? ', ' + c.code_size.toLocaleString('en-US') + ' bytes of code' : ''}.</p>
              ) : null}
              <h4>Why it is flagged</h4>
              {c.labels.length ? (
                <ul className="whys">{c.labels.map(l => { const [n, d] = labelInfo(l); return <li key={l}><b>{n}.</b> <span className="muted">{d}</span></li> })}</ul>
              ) : <p className="muted">No detector label recorded.</p>}
              <h4>Timeline</h4>
              <Timeline c={c} now={model.now} />
              <h4>Subjects</h4>
              <ul className="subjects">{subj.map(([k, v], i) => <li key={i}><span>{k}</span><FullId value={v} chain={c.chain} /></li>)}</ul>
              <h4>Cluster</h4>
              {cl ? (
                <ul className="links">
                  <li><span className="mono small">{cl.cluster}</span><span className="muted small">{plural(cl.members.length, 'drainer')} share {plural(cl.shared_wallets.length, 'payout wallet')}</span></li>
                  {mates.map(m => <li key={m.key}><button className="linkbtn" onClick={() => onOpen(m)}>{m.tier} {m.title}</button><Addr value={m.address} chain={m.chain} /></li>)}
                </ul>
              ) : <p className="muted">Not part of a known operator cluster.</p>}
            </section>
            <section className="page right">
              <h4 style={{ marginTop: 0 }}>Evidence</h4>
              {c.evidence.length ? (
                <ol className="exhibits">{c.evidence.map((e, i) => <li key={i}><b>{labelInfo(e.type)[0]}</b>, {fmtStamp(e.ts)}. <Tx chain={c.chain} tx={e.tx}>Transaction</Tx><p>{e.detail}</p></li>)}</ol>
              ) : <p className="muted">No evidence row published for this subject.</p>}
              <h4>Latest drains</h4>
              {recent.length ? (
                <ul className="links">{recent.map(d => (
                  <li key={d.tx + d.victim}><span className="muted small">{fmtDay(d.ts)}, {fmtTime(d.ts)}</span><span>{d.usd == null ? <span className="muted">unpriced {d.symbol || ''}</span> : fmtUSD(d.usd)}</span><span className="small">from <Addr value={d.victim} chain={d.chain} /></span><Tx chain={d.chain} tx={d.tx}>tx</Tx></li>
                ))}{c.drainList.length > recent.length ? <li className="muted small">and {c.drainList.length - recent.length} more in the published list</li> : null}</ul>
              ) : <p className="muted">None in the latest published drains.</p>}
              <h4>Where the money surfaced</h4>
              {reached.length ? (
                <ol className="exhibits" style={{ '--start': c.evidence.length } as React.CSSProperties}>
                  {reached.map((v, i) => <li key={i}><b>{v.entity || 'An exchange'}</b> received {v.usd != null ? fmtUSD(v.usd) : 'an unpriced amount' + (v.symbol ? ' of ' + v.symbol : '')} from {v.role === 'drainer' ? 'the ' + what : 'a payout wallet'}. <Tx chain={c.chain} tx={v.tx}>Transaction</Tx><p>{kindText(v.kind)}{v.confidence ? ', ' + v.confidence + ' confidence' : ''}.</p></li>)}
                </ol>
              ) : <p className="muted">No exchange deposit seen yet.</p>}
              <h4>Funds that can still be frozen</h4>
              <Freeze c={c} model={model} />
              <h4>Deployer</h4>
              <Deployer c={c} />
              <h4>Same {what} on other chains</h4>
              {twins.length ? (
                <ul className="links">{twins.map(t => <li key={t.key}><button className="linkbtn" onClick={() => onOpen(t)}>{chainLong(t.chain)}, {t.tier} {TIER_NAME[t.tier].toLowerCase()}</button><span className="muted small">{fmtUSD(t.usd)} taken there</span></li>)}</ul>
              ) : (c.cross_chain || []).length ? (
                <p className="muted">Flagged on {(c.cross_chain || []).map(x => chainShort(x.chain) + ' (' + x.tier + ')').join(', ')}; not in the published list.</p>
              ) : <p className="muted">Not seen on another chain.</p>}
              <div className="spread-tools">
                <button className="btn" onClick={() => window.print()}>Print this file</button>
                <button className="btn" onClick={copyLink}>{linkCopied ? 'Link copied' : 'Copy link to this file'}</button>
              </div>
            </section>
          </DialogPrimitive.Content>
        </DialogPrimitive.Overlay>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  )
}
