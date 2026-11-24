import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { ago, fmtInt, fmtStamp } from '@/lib/format'
import type { Model } from '@/lib/model'
import type { ChainInfo } from '@/lib/types'
import { chainLong, chainShort } from '@/lib/vocab'

const lagText = (c: ChainInfo) => {
  const sec = c.block_sec ? c.lag_blocks * c.block_sec : null
  const t = sec == null ? '' : sec < 90 ? ', about ' + Math.max(1, Math.round(sec)) + ' s' : sec < 5400 ? ', about ' + Math.round(sec / 60) + ' min' : ', about ' + Math.round(sec / 3600) + ' h'
  return c.lag_blocks ? fmtInt(c.lag_blocks) + ' blocks behind' + t : 'at the head'
}

/** Compact scan status under the masthead: lag and "not scanned" gaps per chain. */
export function Coverage({ model }: { model: Model }) {
  if (!model.chains.length) return <p className="coverage muted">No chain has been scanned yet.</p>
  return (
    <div className="coverage" aria-label="Scan coverage">
      {model.chains.map(([ch, c]) => (
        <span key={ch} className="cov">
          <b>{chainShort(ch)}</b> {lagText(c)}, scanned {c.last_scan_at ? ago(c.last_scan_at) : 'never'}
          {c.gap_blocks ? (
            <Tooltip>
              <TooltipTrigger asChild>
                <button type="button" className="gapbtn">not scanned: {fmtInt(c.gap_blocks)} blocks</button>
              </TooltipTrigger>
              <TooltipContent className="gaptip">
                <span>
                  {(c.gaps || []).length} skipped range{(c.gaps || []).length === 1 ? '' : 's'} on {chainLong(ch)} (latest shown): {(c.gaps || []).slice(-4).map(g => fmtInt(g.from) + '–' + fmtInt(g.to)).join(', ')}. Drains in those blocks are missing here.
                </span>
              </TooltipContent>
            </Tooltip>
          ) : null}
          {c.note ? <span className="covnote" title={c.note}> ({c.note})</span> : null}
        </span>
      ))}
    </div>
  )
}

/** Full coverage table in the method section. */
export function CoverageNotes({ model }: { model: Model }) {
  if (!model.chains.length) return null
  return (
    <div className="card card-pad margin ruled ledger-wrap coverage-table">
      <h3>Scan coverage</h3>
      <table className="ledger">
        <thead><tr><th>Chain</th><th className="r">Scanned to</th><th className="r">Head</th><th>Behind</th><th className="hide-sm">Last scan</th><th>Not scanned</th></tr></thead>
        <tbody>
          {model.chains.map(([ch, c]) => (
            <tr key={ch}>
              <td>{chainLong(ch)}</td>
              <td className="r">{fmtInt(c.cursor_block)}</td>
              <td className="r">{fmtInt(c.head_block)}</td>
              <td>{lagText(c)}</td>
              <td className="hide-sm muted">{c.last_scan_at ? fmtStamp(c.last_scan_at) : 'never'}</td>
              <td>{c.gap_blocks ? <>{fmtInt(c.gap_blocks)} blocks in {(c.gaps || []).length} range{(c.gaps || []).length === 1 ? '' : 's'}</> : <span className="muted">none recorded</span>}{c.note ? <div className="muted small wrap">{c.note}</div> : null}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {model.chains.some(([, c]) => c.gap_blocks) ? (
        <ul className="gaplist">
          {model.chains.filter(([, c]) => (c.gaps || []).length).map(([ch, c]) => (
            <li key={ch}><b>{chainShort(ch)}</b> <span className="muted">skipped ranges:</span> <span className="mono small">{(c.gaps || []).map(g => fmtInt(g.from) + '–' + fmtInt(g.to)).join(', ')}</span></li>
          ))}
        </ul>
      ) : null}
    </div>
  )
}
