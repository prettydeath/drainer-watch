import { useState } from 'react'
import { fmtDay, fmtTime, fmtUSD } from '@/lib/format'
import type { Case, Model } from '@/lib/model'
import { chainShort } from '@/lib/vocab'
import { Addr, Tx, tv } from './shared'

const PAGE = 14

// explorer link only when the chain is unambiguous (an EVM deposit address may sit on several chains)
const depositChain = (a: string, chains: string[]) => {
  if (/^T[1-9A-HJ-NP-Za-km-z]{33}$/.test(a)) return 'tron'
  const evm = chains.filter(c => c !== 'tron')
  return evm.length === 1 ? evm[0] : undefined
}

export function DrainLedger({ model, onOpen }: { model: Model; onOpen: (c: Case) => void }) {
  const strong = model.drains.filter(d => d.tier && d.tier !== 'T3')
  const [all, setAll] = useState(strong.length === 0)
  const [n, setN] = useState(PAGE)
  const rows = (all ? model.drains.filter(d => d.tier) : strong)
  return (
    <div className="card card-pad margin ruled ledger-wrap">
      <div className="filters small-filters" role="group" aria-label="Which drains">
        <button className="chipf" aria-pressed={!all} onClick={() => { setAll(false); setN(PAGE) }}>Confirmed and strong</button>
        <button className="chipf" aria-pressed={all} onClick={() => { setAll(true); setN(PAGE) }}>All tracked, with suspects</button>
      </div>
      {rows.length ? (
        <table className="ledger">
          <thead><tr><th>Time, UTC</th><th>Tier</th><th>Drainer</th><th className="hide-sm">Victim</th><th className="r">Value</th><th className="r">Proof</th></tr></thead>
          <tbody>
            {rows.slice(0, n).map(d => {
              const c = model.byKey.get(d.key)
              return (
                <tr key={d.tx + d.victim + d.drainer} className="row" data-drain-row={d.key} style={{ '--tc': tv(d.tier) } as React.CSSProperties} onClick={() => c && onOpen(c)}
                  tabIndex={0} onKeyDown={e => { if (e.key === 'Enter' && c) onOpen(c) }} aria-label={'Open case for drain at ' + fmtDay(d.ts) + ' ' + fmtTime(d.ts)}>
                  <td className="muted">{fmtDay(d.ts)}, {fmtTime(d.ts)}</td>
                  <td><span className="tg">{d.tier}</span></td>
                  <td><Addr value={d.drainer} chain={d.chain} /> <span className="muted small">{chainShort(d.chain)}</span></td>
                  <td className="hide-sm"><Addr value={d.victim} chain={d.chain} /></td>
                  <td className="r">{d.usd == null ? <span className="muted">unpriced{d.symbol ? ' ' + d.symbol : ''}</span> : fmtUSD(d.usd)}</td>
                  <td className="r"><Tx chain={d.chain} tx={d.tx}>tx</Tx></td>
                </tr>
              )
            })}
          </tbody>
        </table>
      ) : <p className="muted empty">No drain by a tracked drainer in the published list yet.</p>}
      {rows.length > n ? <button className="btn more-btn" onClick={() => setN(x => x + PAGE)}>Show {Math.min(PAGE, rows.length - n)} more</button> : null}
    </div>
  )
}

export function Exposure({ model }: { model: Model }) {
  const v = model.data.vasps.slice().sort((a, b) => b.usd - a.usd || b.links - a.links)
  if (!v.length) return <div className="card card-pad margin"><p className="muted empty">No exchange deposit seen yet. Payout wallets are followed one hop; deposits show up here when they are swept on to an exchange hot wallet.</p></div>
  const max = Math.max(v[0].usd, 1)
  return (
    <div className="card card-pad margin">
      {v.map(x => (
        <div className="vx" key={x.entity}>
          <b>{x.entity}</b><span className="num">{x.usd ? fmtUSD(x.usd) : <span className="muted">unpriced</span>}</span>
          <div className="bar"><i style={{ width: Math.max(1.5, (100 * x.usd) / max) + '%' }} /></div>
          <div className="deps"><span>{x.links} link{x.links === 1 ? '' : 's'} from {x.subjects} subject{x.subjects === 1 ? '' : 's'}, {x.chains.map(chainShort).join(', ')}</span></div>
          {x.deposit_addresses.length ? <div className="deps">{x.deposit_addresses.slice(0, 8).map(a => <Addr key={a} value={a} chain={depositChain(a, x.chains)} link />)}{x.deposit_addresses.length > 8 ? <span>and {x.deposit_addresses.length - 8} more</span> : null}</div> : null}
        </div>
      ))}
    </div>
  )
}
