import { useEffect, useMemo, useRef, useState } from 'react'
import { animate, createMotionPath, createScope } from 'animejs'
import { buildFlow, layoutFlow } from '@/lib/flow'
import { fmtUSD } from '@/lib/format'
import type { Case } from '@/lib/model'
import { reduceMotion, tv } from './shared'

const HEIGHT = 440
const MIN_W = 820

/** Money flow hero. Motion: particles along each link (anime.js createMotionPath), off with reduced motion. */
export function Flow({ cases, onOpen }: { cases: Case[]; onOpen: (c: Case) => void }) {
  const box = useRef<HTMLDivElement>(null)
  const svg = useRef<SVGSVGElement>(null)
  const [W, setW] = useState(1180)
  const [hi, setHi] = useState<string | null>(null)
  useEffect(() => {
    if (!box.current || typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(e => setW(Math.max(MIN_W, Math.round(e[0].contentRect.width))))
    ro.observe(box.current)
    return () => ro.disconnect()
  }, [])
  const model = useMemo(() => buildFlow(cases), [cases])
  const lay = useMemo(() => layoutFlow(model, W, HEIGHT), [model, W])

  useEffect(() => {
    const root = svg.current
    if (!root || reduceMotion() || !model.total) return
    const g = root.querySelector('.particles') as SVGGElement
    const scope = createScope({ root: { current: root } as unknown as React.RefObject<HTMLElement> }).add(() => {
      lay.links.forEach((l, i) => {
        if (l.w < 1.5) return
        const n = Math.max(1, Math.min(4, Math.round((l.v / model.total) * 22)))
        const path = root.querySelector('[data-l="' + i + '"]') as SVGPathElement | null
        if (!path) return
        for (let j = 0; j < n; j++) {
          const c = document.createElementNS('http://www.w3.org/2000/svg', 'circle')
          c.setAttribute('r', String(Math.min(3, 1.6 + l.w / 14)))
          c.setAttribute('class', 'dotp')
          c.setAttribute('fill', l.S.col === 0 ? tv(l.tier) : 'var(--node)')
          c.setAttribute('fill-opacity', l.S.col === 0 ? '.95' : '.5')
          g.appendChild(c)
          const dur = 3600 + ((i * 137) % 1600)
          animate(c, { ...createMotionPath(path), duration: dur, ease: 'linear', loop: true, delay: (j / n) * dur + (i % 7) * 90 })
        }
      })
    })
    return () => {
      scope.revert()
      g.replaceChildren()
    }
  }, [lay, model.total])

  if (!lay.nodes.length) return null
  return (
    <div className="flow-scroll" ref={box}>
      <div className="flow-cols"><div>Victims</div><div>Drainers</div><div>Payout wallets</div><div>Exchanges</div></div>
      <svg ref={svg} className="flow" width={W} height={HEIGHT + 4} viewBox={`0 -2 ${W} ${HEIGHT + 4}`} role="img" aria-label="Flow of drained money from victims to drainers, payout wallets and exchanges">
        <g>
          {lay.links.map((l, i) => (
            <path key={l.s + '>' + l.t} data-l={i} className={'lnk' + (hi && (hi === l.s || hi === l.t) ? ' hi' : '')} d={l.d} stroke={l.S.col === 0 ? tv(l.tier) : 'var(--flow)'} strokeWidth={l.w}>
              <title>{l.S.label + ' to ' + l.T.label + ': ' + fmtUSD(l.v)}</title>
            </path>
          ))}
        </g>
        <g className="particles" />
        {lay.nodes.map(n => {
          const c = n.c
          return (
            <g key={n.id} className={'node' + (c ? ' click' : '')} data-flow-node={c ? c.key : undefined} onMouseEnter={() => setHi(n.id)} onMouseLeave={() => setHi(null)}
              onClick={c ? () => onOpen(c) : undefined} tabIndex={c ? 0 : undefined} role={c ? 'button' : undefined}
              aria-label={c ? 'Open case ' + c.caseNo + ', ' + c.address : undefined}
              onKeyDown={c ? e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onOpen(c) } } : undefined}>
              <rect x={n.x} y={n.y} width={lay.nw} height={n.h} rx={1.5} style={c ? { fill: tv(c.tier) } : undefined} />
              <text x={n.col === 3 ? n.x - 8 : n.x + lay.nw + 8} y={n.y + n.h / 2} dy="0.35em" textAnchor={n.col === 3 ? 'end' : 'start'} className={n.mono ? 'mono' : ''}>
                {n.label}
                <tspan className="v" dx="6" style={{ fontFamily: 'var(--font-serif)' }}>{fmtUSD(n.v, true)}</tspan>
              </text>
              {c ? <title>{c.tier + ' ' + c.title + ', ' + c.address}</title> : null}
            </g>
          )
        })}
      </svg>
    </div>
  )
}
