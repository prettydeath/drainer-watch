import { useEffect, useMemo, useState } from 'react'
import { Input } from '@/components/ui/input'
import { ago, fmtUSD, mid, plural } from '@/lib/format'
import { search, type Case, type Model } from '@/lib/model'
import type { Tier } from '@/lib/types'
import { TIER_BLURB, TIER_NAME, TIER_ORDER, chainLong, chainShort } from '@/lib/vocab'
import { Addr, tv, useMedia } from './shared'

function FileCard({ c, onOpen }: { c: Case; onOpen: (c: Case) => void }) {
  return (
    <button className="file" data-case-row={c.key} onClick={() => onOpen(c)} style={{ '--tc': tv(c.tier) } as React.CSSProperties} aria-label={'Open case ' + c.caseNo + ', ' + c.tier + ' ' + c.title + ', ' + c.address}>
      <span className="tab"><i /><b>{c.tier}</b> {TIER_NAME[c.tier].toLowerCase()}</span>
      <div className="card ruled">
        <span className="stamp" title={'Score ' + c.score + ' of 100'}>{c.score}</span>
        <h3>{c.title}</h3>
        <div className="addr-line mono">{mid(c.address, 10, 6)}{c.isWallet ? <span className="kind"> wallet</span> : null}</div>
        <dl>
          <dt>Chain</dt><dd>{chainLong(c.chain)}</dd>
          <dt>Victims</dt><dd>{c.victims}</dd>
          <dt>Taken</dt><dd>{fmtUSD(c.usd)}</dd>
          <dt>Last drain</dt><dd>{ago(c.last_seen)}</dd>
        </dl>
        <p className="compact">{chainShort(c.chain)} · {plural(c.victims, 'victim')} · {fmtUSD(c.usd)} · {ago(c.last_seen)}</p>
      </div>
    </button>
  )
}

function Group({ tier, files, onOpen, defaultOpen, page }: { tier: Tier; files: Case[]; onOpen: (c: Case) => void; defaultOpen: boolean; page: number }) {
  const [open, setOpen] = useState(defaultOpen)
  const [n, setN] = useState(page)
  useEffect(() => setOpen(defaultOpen), [defaultOpen])
  useEffect(() => setN(page), [page, files])
  const id = 'grp-' + tier
  return (
    <div className="group" data-group={tier}>
      <div className="group-h" style={{ '--tc': tv(tier) } as React.CSSProperties}>
        <i /><h3>{TIER_NAME[tier]}</h3>
        <p>{plural(files.length, 'file')}, {TIER_BLURB[tier]}</p>
        <button className="btn group-toggle" aria-expanded={open} aria-controls={id} onClick={() => setOpen(o => !o)}>{open ? 'Collapse' : 'Show ' + files.length}</button>
      </div>
      {open ? (
        <div id={id}>
          <div className="files">{files.slice(0, n).map(c => <FileCard key={c.key} c={c} onOpen={onOpen} />)}</div>
          {files.length > n ? (
            <button className="btn more-btn" onClick={() => setN(x => x + page)}>Show {Math.min(page, files.length - n)} more of {files.length - n}</button>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}

export function CaseFiles({ model, onOpen, query, setQuery }: { model: Model; onOpen: (c: Case) => void; query: string; setQuery: (q: string) => void }) {
  const [chain, setChain] = useState('all')
  const small = useMedia('(max-width: 640px)')
  const page = small ? 6 : 24
  const chains = useMemo(() => [...new Set([...model.chains.map(c => c[0]), ...model.cases.map(c => c.chain)])], [model])
  const q = query.trim().toLowerCase()
  const hits = useMemo(() => search(model, query), [model, query])
  const list = useMemo(() => {
    const keys = new Set(hits.map(h => h.key))
    return model.cases.filter(c => (chain === 'all' || c.chain === chain) &&
      (!q || keys.has(c.key) || c.title.toLowerCase().includes(q) || (c.family || '').toLowerCase().includes(q) || c.labels.some(l => l.includes(q))))
  }, [model, chain, q, hits])
  const strongCount = list.filter(c => c.tier !== 'T3').length
  return (
    <>
      <div className="filters" role="group" aria-label="Filter case files">
        {['all', ...chains].map(ch => (
          <button key={ch} className="chipf" aria-pressed={chain === ch} onClick={() => setChain(ch)}>{ch === 'all' ? 'All chains' : chainLong(ch)}</button>
        ))}
        <Input className="search" type="search" placeholder="Find any address, transaction or family" value={query} onChange={e => setQuery(e.target.value)} aria-label="Search every address and transaction" />
      </div>
      {q.length >= 3 && hits.length ? (
        <div className="card card-pad margin hits" role="region" aria-label="Address matches">
          <p className="muted small">{hits.length >= 60 ? 'First 60 matches' : plural(hits.length, 'match', 'matches')} across every address and transaction in the data:</p>
          <ul>
            {hits.slice(0, 12).map((h, i) => {
              const c = model.byKey.get(h.key)
              if (!c) return null
              return (
                <li key={i}>
                  <Addr value={h.value} chain={c.chain} h={10} t={6} link />
                  <span className="muted small">{h.role} of</span>
                  <button className="linkbtn" onClick={() => onOpen(c)} style={{ '--tc': tv(c.tier) } as React.CSSProperties}><b className="tg">{c.tier}</b> {c.title} {c.caseNo}</button>
                </li>
              )
            })}
          </ul>
          {hits.length > 12 ? <p className="muted small">and {hits.length - 12} more; the matching files are listed below.</p> : null}
        </div>
      ) : q.length >= 3 ? <p className="muted">No address, transaction or family matches “{query.trim()}”.</p> : null}
      {TIER_ORDER.map(t => {
        const files = list.filter(c => c.tier === t)
        if (!files.length) return null
        return <Group key={t} tier={t} files={files} onOpen={onOpen} page={page} defaultOpen={t !== 'T3' || !!q || strongCount === 0} />
      })}
      {!list.length && !q ? <p className="muted">{model.cases.length ? 'No file on this chain.' : 'No case file yet: nothing has been flagged.'}</p> : null}
    </>
  )
}
