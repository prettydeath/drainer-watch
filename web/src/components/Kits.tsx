import { useEffect, useMemo, useRef, useState } from 'react'
import { animate, createScope } from 'animejs'
import { PolarAngleAxis, PolarGrid, PolarRadiusAxis, Radar, RadarChart, RadialBar, RadialBarChart } from 'recharts'
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from '@/components/ui/chart'
import { DAY, H, ago, fmtUSD, plural } from '@/lib/format'
import type { Case, Family, Model } from '@/lib/model'
import { chainShort, famSourceNote } from '@/lib/vocab'
import { Addr, reduceMotion, tv } from './shared'

const MAX_BLIPS_PER_FAMILY = 120

function Scope({ fams, now, onOpen }: { fams: Family[]; now: number; onOpen: (c: Case) => void }) {
  const S = 520, C = S / 2, R0 = 26, R1 = C - 44, PERIOD = 6000
  const svg = useRef<SVGSVGElement>(null)
  const rings: [number, string][] = [[H, '1 h'], [6 * H, '6 h'], [DAY, '1 d'], [7 * DAY, '7 d'], [30 * DAY, '30 d']]
  const rOf = (age: number) => R0 + (R1 - R0) * Math.min(1, Math.log(1 + Math.max(age, 60e3) / 60e3) / Math.log(1 + (30 * DAY) / 60e3))
  const seg = 360 / Math.max(1, fams.length)
  const blips = useMemo(() => {
    const out: { c: Case; x: number; y: number; deg: number; size: number }[] = []
    fams.forEach((f, fi) =>
      f.contracts.slice(0, MAX_BLIPS_PER_FAMILY).forEach((c, ci) => {
        const a = ((fi * seg + seg * (0.18 + 0.64 * ((ci * 0.618) % 1)) - 90) * Math.PI) / 180
        const t = Date.parse(c.last_seen)
        const r = rOf(Number.isFinite(t) ? now - t : 30 * DAY)
        out.push({ c, x: C + r * Math.cos(a), y: C + r * Math.sin(a), deg: ((a * 180) / Math.PI + 90 + 360) % 360, size: 3.5 + Math.min(5, Math.log10(1 + c.usd)) })
      }),
    )
    return out
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fams, now])
  useEffect(() => {
    const root = svg.current
    if (!root || reduceMotion()) return
    const scope = createScope({ root: root as unknown as HTMLElement }).add(() => {
      animate(root.querySelector('.sweep')!, { rotate: [0, 360], duration: PERIOD, ease: 'linear', loop: true })
      const halos = root.querySelectorAll<SVGCircleElement>('.halo')
      if (halos.length)
        animate(halos, {
          opacity: [0.9, 0],
          r: (el: unknown) => { const r = Number((el as SVGElement).dataset.r); return [r, r + 12] },
          duration: 1400, ease: 'out(2)', loop: true, loopDelay: PERIOD - 1400,
          delay: (el: unknown) => (Number((el as SVGElement).dataset.deg) / 360) * PERIOD,
        })
    })
    return () => scope.revert()
  }, [blips])
  const shown = fams.reduce((s, f) => s + Math.min(MAX_BLIPS_PER_FAMILY, f.contracts.length), 0)
  const total = fams.reduce((s, f) => s + f.contracts.length, 0)
  return (
    <>
      <svg ref={svg} className="scope" viewBox={`-74 0 ${S + 148} ${S}`} role="img" aria-label="Drainers by kit family and time since their last drain">
        <defs><linearGradient id="sweepg7" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stopColor="var(--sweep)" stopOpacity="0" /><stop offset="1" stopColor="var(--sweep)" stopOpacity=".22" /></linearGradient></defs>
        <circle className="ring outer" cx={C} cy={C} r={R1 + 6} />
        {rings.map(([t, l]) => <g key={l}><circle className="ring" cx={C} cy={C} r={rOf(t)} /><text className="ring-label" x={C + 4} y={C - rOf(t) - 3}>{l}</text></g>)}
        {fams.map((f, i) => {
          const a = ((i * seg - 90) * Math.PI) / 180, am = (((i + 0.5) * seg - 90) * Math.PI) / 180, lr = R1 + 22
          return (
            <g key={f.key || '_'}>
              {fams.length > 1 ? <line className="spoke" x1={C + R0 * Math.cos(a)} y1={C + R0 * Math.sin(a)} x2={C + (R1 + 6) * Math.cos(a)} y2={C + (R1 + 6) * Math.sin(a)} /> : null}
              <text className="sector-label" x={C + lr * Math.cos(am)} y={C + lr * Math.sin(am)} dy="0.35em" textAnchor={Math.abs(Math.cos(am)) < 0.3 ? 'middle' : Math.cos(am) > 0 ? 'start' : 'end'}>
                {(n => (n.length > 24 ? n.slice(0, 23) + '…' : n))(f.name.replace('Code family ', 'Family ').replace(' approval kit', '').replace('MS generated bait', 'MS generated'))}
              </text>
            </g>
          )
        })}
        <g className="sweep" style={{ transformOrigin: `${C}px ${C}px` }}>
          <path d={`M${C},${C} L${C},${C - R1 - 6} A${R1 + 6},${R1 + 6} 0 0,1 ${C + (R1 + 6) * Math.sin(Math.PI / 5)},${C - (R1 + 6) * Math.cos(Math.PI / 5)} Z`} fill="url(#sweepg7)" transform={`rotate(-36 ${C} ${C})`} />
          <line x1={C} y1={C} x2={C} y2={C - R1 - 6} stroke="var(--sweep)" strokeWidth="1.5" strokeOpacity=".8" />
        </g>
        <circle cx={C} cy={C} r={3} fill="var(--sweep)" />
        {blips.map(b => (
          <g key={b.c.key} className="blip" data-blip={b.c.key} tabIndex={0} role="button" aria-label={'Open ' + b.c.tier + ' case ' + b.c.address}
            onClick={() => onOpen(b.c)} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onOpen(b.c) } }}>
            <circle className="halo" cx={b.x} cy={b.y} r={b.size} data-r={b.size} data-deg={b.deg} stroke={tv(b.c.tier)} />
            <circle className="core" cx={b.x} cy={b.y} r={b.size} fill={tv(b.c.tier)} />
            <title>{b.c.tier + ' ' + b.c.title + ', ' + b.c.address + ', last drain ' + ago(b.c.last_seen)}</title>
          </g>
        ))}
      </svg>
      {shown < total ? <p className="muted small" style={{ margin: '4px 0 0' }}>Showing the {shown} highest-ranked of {total} marks; every drainer is in the case files.</p> : null}
    </>
  )
}

const radarConfig = { value: { label: 'Uses it', color: 'var(--chart-1)' } } satisfies ChartConfig
const ringConfig = { v: { label: 'Activity', color: 'var(--chart-1)' } } satisfies ChartConfig

function MethodBars({ f }: { f: Family }) {
  const used = f.profile.filter(p => p.value > 0)
  return (
    <ul className="mbars">
      {used.map(p => <li key={p.axis}><span>{p.axis}</span><span className="track"><i style={{ width: p.value + '%' }} /></span><span>{p.value}%</span></li>)}
      <li className="none" style={{ display: 'block' }}>{used.length ? 'No other method seen in its evidence.' : 'No method signal in its evidence yet.'}</li>
    </ul>
  )
}

function FamilyCard({ f, maxD7, onOpen }: { f: Family; maxD7: number; onOpen: (c: Case) => void }) {
  const pct = Math.round((100 * f.d7) / maxD7)
  const top = f.contracts.slice(0, 3)
  return (
    <article className="card fam margin">
      <h3 title={f.key ? 'Code family hash ' + f.key : undefined}>{f.name}<small>{plural(f.contracts.length, 'drainer')}, {fmtUSD(f.usd)}</small></h3>
      {f.source && f.source !== 'kit' ? <p className="famsrc">{famSourceNote(f.source)}{f.key ? <>, code hash <span className="mono">{f.key}</span></> : null}</p> : null}
      <p className="blurb">{f.blurb}</p>
      <div className="profile">
        {f.axes >= 3 ? (
          <ChartContainer config={radarConfig} className="aspect-auto h-[176px] w-full min-w-0" initialDimension={{ width: 260, height: 176 }}>
            <RadarChart accessibilityLayer data={f.profile} outerRadius="66%" margin={{ top: 4, right: 30, bottom: 4, left: 30 }}>
              <PolarGrid stroke="var(--rule)" />
              <PolarAngleAxis dataKey="axis" tick={{ fill: 'var(--muted-foreground)', fontSize: 11.5, fontFamily: 'var(--font-serif)' }} />
              <PolarRadiusAxis domain={[0, 100]} tick={false} axisLine={false} />
              <ChartTooltip cursor={false} content={<ChartTooltipContent formatter={v => <span>Uses it: <b className="num">{String(v)}%</b> of members</span>} />} />
              <Radar dataKey="value" stroke="var(--color-value)" fill="var(--color-value)" fillOpacity={0.18} strokeWidth={1.5} dot={{ r: 2, fill: 'var(--color-value)' }} isAnimationActive={false} />
            </RadarChart>
          </ChartContainer>
        ) : <MethodBars f={f} />}
        <div className="act" title="Drains in the last 7 days, compared with the busiest family">
          <div className="ring7">
            <ChartContainer config={ringConfig} className="aspect-auto h-full w-full" initialDimension={{ width: 92, height: 92 }}>
              <RadialBarChart data={[{ v: pct }]} innerRadius="74%" outerRadius="100%" startAngle={90} endAngle={-270}>
                <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
                <RadialBar dataKey="v" fill="var(--color-v)" background={{ fill: 'var(--muted)' }} cornerRadius={6} isAnimationActive={false} />
              </RadialBarChart>
            </ChartContainer>
            <div className="c"><b>{f.d7}</b></div>
          </div>
          <span>drains in 7 days</span>
        </div>
      </div>
      <div className="members">
        {top.map(c => (
          <div key={c.key} className="member" style={{ '--tc': tv(c.tier) } as React.CSSProperties} onClick={() => onOpen(c)} role="button" tabIndex={0}
            aria-label={'Open case ' + c.caseNo} onKeyDown={e => { if (e.key === 'Enter') onOpen(c) }}>
            <span className="t">{c.tier}</span>
            <span><Addr value={c.address} chain={c.chain} /> <span className="muted">{chainShort(c.chain)}</span></span>
            <span className="muted">{ago(c.last_seen)}</span>
          </div>
        ))}
        {f.contracts.length > top.length ? <div className="member muted more">and {f.contracts.length - top.length} more in the case files</div> : null}
      </div>
    </article>
  )
}

export default function Kits({ model, onOpen }: { model: Model; onOpen: (c: Case) => void }) {
  const [all, setAll] = useState(false)
  const maxD7 = Math.max(...model.fams.map(f => f.d7), 1)
  const LIMIT = 6
  const fams = all ? model.fams : model.fams.slice(0, LIMIT)
  return (
    <div className="kits">
      <div className="card scope-card">
        <p className="muted small" style={{ margin: '0 0 6px' }}>Each mark is a drainer, in its family's sector. Nearer the centre means a more recent drain; size is value taken.</p>
        <div className="scope-box"><Scope fams={model.fams} now={model.now} onOpen={onOpen} /></div>
      </div>
      <div>
        <div className="fam-grid">{fams.map(f => <FamilyCard key={f.key || '_'} f={f} maxD7={maxD7} onOpen={onOpen} />)}</div>
        {model.fams.length > LIMIT ? <button className="btn more-btn" onClick={() => setAll(a => !a)} aria-expanded={all}>{all ? 'Show fewer families' : 'Show all ' + model.fams.length + ' families'}</button> : null}
      </div>
    </div>
  )
}
