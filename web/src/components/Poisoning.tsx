import { ago, plural } from '@/lib/format'
import type { Model } from '@/lib/model'
import { chainShort } from '@/lib/vocab'
import { Addr } from './shared'

const SHOWN = 25

/** Address poisoning (backend policy.py, data.json `poisoning`): kept apart from the drainers and out of every total. */
export function Poisoning({ model }: { model: Model }) {
  const rows = model.data.poisoning ?? []
  const n = model.data.totals.poisoning ?? rows.length
  if (!n) return null
  return (
    <section className="sect" id="poisoning">
      <div className="sect-h">
        <h2>Address poisoning</h2>
        <p>{plural(n, 'address', 'addresses')} send look-alike or zero-value transfers so that a victim copies the wrong address later. A different scam from drainers: they are not in the case files or the totals above.</p>
      </div>
      <div className="card ruled margin">
        <table className="ledger">
          <thead><tr><th>Address</th><th>Chain</th><th>Targets</th><th>Last seen</th></tr></thead>
          <tbody>
            {rows.slice(0, SHOWN).map(r => (
              <tr key={r.chain + ':' + r.address}>
                <td><Addr value={r.address} chain={r.chain} link /></td>
                <td>{chainShort(r.chain)}</td>
                <td className="num">{r.victims}</td>
                <td className="muted">{r.last_seen ? ago(r.last_seen) : ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {n > SHOWN ? <p className="muted small">The {SHOWN} most recent of {n}; the full list is in data.json.</p> : null}
      </div>
    </section>
  )
}
