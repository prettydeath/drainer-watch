import { Suspense, lazy, useCallback, useEffect, useMemo, useState } from 'react'
import { TooltipProvider } from '@/components/ui/tooltip'
import { Boundary } from '@/components/Boundary'
import { Coverage, CoverageNotes } from '@/components/Coverage'
import { CaseFiles } from '@/components/CaseFiles'
import { DrainLedger, Exposure } from '@/components/Ledger'
import { Flow } from '@/components/Flow'
import { ThemeToggle, tv, useTheme } from '@/components/shared'
import { ago, fmtInt, fmtStamp, fmtUSD, plural } from '@/lib/format'
import { buildModel, type Case, type Model } from '@/lib/model'
import { parseRoute, type Tab } from '@/lib/analytics'
import type { DataJson } from '@/lib/types'
import { TIERS, TIER_NAME, TIER_ORDER } from '@/lib/vocab'

const Kits = lazy(() => import('@/components/Kits'))
const Analytics = lazy(() => import('@/components/Analytics'))
const CaseSpread = lazy(() => import('@/components/CaseSpread'))

type Load = { state: 'loading' } | { state: 'error'; error: string } | { state: 'ready'; model: Model }

const parseHash = () => parseRoute(location.hash).caseRef

export default function App({ data }: { data?: DataJson }) {
  const [load, setLoad] = useState<Load>(() => (data ? { state: 'ready', model: buildModel(data) } : { state: 'loading' }))
  useEffect(() => {
    if (data) return
    let off = false
    fetch('data.json', { cache: 'no-cache' })
      .then(r => {
        if (!r.ok) throw new Error('HTTP ' + r.status)
        return r.json() as Promise<DataJson>
      })
      .then(d => { if (!off) setLoad({ state: 'ready', model: buildModel(d) }) })
      .catch(e => { if (!off) setLoad({ state: 'error', error: String(e && e.message ? e.message : e) }) })
    return () => { off = true }
  }, [data])
  const [theme, toggle] = useTheme()
  return (
    <TooltipProvider delayDuration={150}>
      {load.state === 'ready' ? (
        <Desk model={load.model} theme={theme} toggle={toggle} />
      ) : (
        <div className="desk">
          <header className="mast"><div><p className="brand">Drainer Watch</p><h1>{load.state === 'loading' ? 'Opening the case files…' : 'The case files could not be loaded.'}</h1></div>
            <div className="tools"><ThemeToggle theme={theme} onToggle={toggle} /></div></header>
          {load.state === 'error' ? <p className="sect muted">data.json: {load.error}. The scanner publishes it every few minutes; try again shortly.</p> : null}
        </div>
      )}
    </TooltipProvider>
  )
}

function Desk({ model, theme, toggle }: { model: Model; theme: string; toggle: () => void }) {
  const [open, setOpen] = useState<Case | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const [withSuspects, setWithSuspects] = useState(false)
  const [tab, setTab] = useState<Tab>(() => parseRoute(location.hash).tab || 'overview')

  // #analytics / #overview pick the tab; deep link #chain:address opens the case spread over either tab
  const syncHash = useCallback(() => {
    const r = parseRoute(location.hash)
    if (r.tab) setTab(r.tab)
    const h = r.caseRef
    if (!h) { setOpen(null); return }
    const c = model.byKey.get(h.chain + ':' + h.address) ||
      model.cases.find(x => x.chain === h.chain && x.address.toLowerCase() === h.address.toLowerCase())
    if (c) { setOpen(c); setNotice(null) } else {
      setOpen(null)
      setNotice(`${h.address} on ${h.chain} has no case file in the current data. Searching every address for it instead.`)
      setQuery(h.address)
      setTab('overview')
      requestAnimationFrame(() => document.getElementById('files')?.scrollIntoView())
    }
  }, [model])
  useEffect(() => {
    syncHash()
    addEventListener('hashchange', syncHash)
    addEventListener('popstate', syncHash)
    return () => { removeEventListener('hashchange', syncHash); removeEventListener('popstate', syncHash) }
  }, [syncHash])
  const openCase = useCallback((c: Case) => {
    setOpen(c)
    const want = '#' + c.key
    if (location.hash !== want) history.pushState(null, '', want)
  }, [])
  const close = useCallback(() => {
    setOpen(null)
    if (parseHash()) history.replaceState(null, '', location.pathname + location.search + (tab === 'analytics' ? '#analytics' : ''))
  }, [tab])
  const pickTab = useCallback((t: Tab) => (e: React.MouseEvent) => {
    e.preventDefault()
    setOpen(null)
    setTab(t)
    if (location.hash !== '#' + t) history.pushState(null, '', '#' + t)
    window.scrollTo(0, 0)
  }, [])

  const t = model.data.totals
  const h = model.headline
  const flowCases = useMemo(() => model.cases.filter(c => withSuspects || c.tier !== 'T3'), [model, withSuspects])
  const flowTotal = flowCases.reduce((s, c) => s + c.usd, 0)
  const activeFams = model.fams.filter(f => f.d7 > 0).length
  const namedFams = model.fams.filter(f => f.key).length
  const stale = Date.now() - model.now > 2 * 3600e3

  return (
    <div className="desk">
      <header className="mast">
        <div>
          <p className="brand">
            <svg width="18" height="18" viewBox="0 0 18 18" aria-hidden="true"><rect x="1.5" y="3" width="15" height="12.5" rx="1.5" fill="none" stroke="currentColor" strokeWidth="1.4" /><path d="M1.5 6.5h15M5 3V1.5h5V3" fill="none" stroke="currentColor" strokeWidth="1.4" /></svg>
            <span>Drainer Watch, case files as of {fmtStamp(model.data.generated_at)}{stale ? <span className="stale"> ({ago(model.data.generated_at)}; the scanner may be behind)</span> : null}</span>
          </p>
          {h.drainers ? (
            <h1><span className="n">{fmtUSD(h.usd)}</span> was taken from {fmtInt(h.victims)} wallets by {plural(h.drainers, 'confirmed or strong drainer', 'confirmed and strong drainers')}; {h.surfaced ? <><span className="n">{fmtUSD(h.surfaced)}</span> of it reached exchanges.</> : 'none of it has been seen reaching an exchange yet.'}</h1>
          ) : (
            <h1>No confirmed or strong drainer on record yet; {plural(h.suspects, 'suspect')} {h.suspects === 1 ? 'is' : 'are'} being watched.</h1>
          )}
          <p className="kicker">Last 24 hours: {fmtUSD(t.usd_24h)} from {plural(t.victims_24h, 'wallet')} in {plural(t.drains_24h, 'drain')}; 7 days: {fmtUSD(t.usd_7d)}. Totals count confirmed and strong drainers only{t.drains_24h_all ? `; ${fmtInt(t.drains_24h_all)} drains by every tracked subject in 24 hours` : ''}.</p>
        </div>
        <div className="tools"><button className="btn hide-sm" onClick={() => window.print()}>Print</button><ThemeToggle theme={theme} onToggle={toggle} /></div>
        <nav className="tabs" role="tablist" aria-label="Views">
          {(['overview', 'analytics'] as Tab[]).map(t => (
            <a key={t} id={'tab-' + t} href={'#' + t} role="tab" aria-selected={tab === t} aria-controls={'panel-' + t} className="tabl" onClick={pickTab(t)}>{t === 'overview' ? 'Overview' : 'Analytics'}</a>
          ))}
        </nav>
      </header>
      <Coverage model={model} />
      {notice ? <p className="notice" role="status">{notice} <button className="linkbtn" onClick={() => setNotice(null)}>Dismiss</button></p> : null}
      {tab === 'analytics' ? (
        <main id="panel-analytics" role="tabpanel" aria-labelledby="tab-analytics">
          <Boundary what="analytics"><Suspense fallback={<p className="sect muted">Loading the analytics…</p>}><Analytics model={model} onOpen={openCase} /></Suspense></Boundary>
        </main>
      ) : (
      <main id="panel-overview" role="tabpanel" aria-labelledby="tab-overview">
      <nav className="toc" aria-label="Sections"><a href="#flow">Where the money went</a><a href="#kits">Kits</a><a href="#files">Case files</a><a href="#drains">Drains and exchanges</a><a href="#method">Method</a></nav>

      <section className="sect" id="flow">
        <div className="sect-h"><h2>Where the money went</h2><p>From the victim's wallet, through the drainer and its payout wallets, to the exchange where it surfaced. Width is value in USD.</p></div>
        <div className="card flowcard">
          <div className="flow-head">
            <p className="swipe">Swipe sideways to follow the money to the exchanges.</p>
            <label className="toggle"><input type="checkbox" checked={withSuspects} onChange={e => setWithSuspects(e.target.checked)} /> Include suspects (T3)</label>
          </div>
          {flowTotal > 0 ? <Boundary what="money flow"><Flow cases={flowCases} onOpen={openCase} /></Boundary> : (
            <p className="empty">{withSuspects ? 'No priced drain is attributed to any tracked subject yet.' : 'No priced drain by a confirmed or strong drainer yet.'}{!withSuspects && model.cases.some(c => c.tier === 'T3' && c.usd > 0) ? <> <button className="linkbtn" onClick={() => setWithSuspects(true)}>Show the suspects' flow</button>.</> : null}</p>
          )}
          <div className="note-row">
            <span>Select a drainer to open its file. Amounts into exchanges are capped at what each wallet received from drains; where no share was observed, value is split by payout transactions.</span>
            <span className="legend">{TIER_ORDER.map(x => <span key={x}><i style={{ background: tv(x) }} />{x} {TIER_NAME[x].toLowerCase()}</span>)}<span><i style={{ background: 'var(--flow)' }} />after the drainer</span></span>
          </div>
        </div>
      </section>

      <section className="sect" id="kits">
        <div className="sect-h"><h2>Kits behind the drains</h2><p>{model.fams.length ? <>{plural(namedFams, 'known kit family', 'known kit families')}{model.fams.some(f => !f.key) ? ' and one unattributed group' : ''}; {activeFams} active in the last 7 days.</> : 'No drainer is tracked yet.'}</p></div>
        {model.fams.length ? <Boundary what="kit radar"><Suspense fallback={<p className="muted">Loading the kit radar…</p>}><Kits model={model} onOpen={openCase} /></Suspense></Boundary> : null}
      </section>

      <section className="sect" id="files">
        <div className="sect-h"><h2>Case files</h2><p>{plural(model.cases.length, 'open file')}: {t.tiers.T1 ?? 0} confirmed, {t.tiers.T2 ?? 0} strong and {t.tiers.T3 ?? 0} suspect{model.cases.length < (t.tiers.T1 + t.tiers.T2 + t.tiers.T3) ? ` (the newest ${model.cases.length} are published)` : ''}.</p></div>
        <CaseFiles model={model} onOpen={openCase} query={query} setQuery={setQuery} />
      </section>

      <section className="sect" id="drains">
        <div className="two">
          <div>
            <div className="sect-h"><h2>Latest drains</h2><p>By tracked drainers, newest first.</p></div>
            <DrainLedger model={model} onOpen={openCase} />
          </div>
          <div>
            <div className="sect-h"><h2>Where it surfaced</h2><p>Exchanges and their probable deposit addresses.</p></div>
            <Exposure model={model} />
          </div>
        </div>
      </section>

      <section className="sect" id="method">
        <div className="sect-h"><h2>Method and limitations</h2><p>How sure we are, and what we cannot see.</p></div>
        <div className="notes">
          <div className="card ruled margin">{TIER_ORDER.map(x => <p key={x} className="tierline" style={{ '--tc': tv(x), marginBottom: 6 } as React.CSSProperties}><i /><span><b>{x} {TIER_NAME[x].toLowerCase()}.</b> {TIERS[x]?.[1]}</span></p>)}</div>
          <div className="card ruled margin"><ul>
            <li>We read blocks on Ethereum, BNB Chain and Base over public RPC, and TRON from TronGrid.</li>
            <li>Families come from code fingerprints; payout roles are inferred from share size.</li>
            <li>A deposit address is probable when funds were swept on to the exchange hot wallet.</li>
            <li>Unpriced tokens count as zero in every total.</li>
          </ul></div>
          <div className="card ruled margin"><ul>
            <li>We cannot see off-chain phishing pages or who runs them.</li>
            <li>A creation transaction we cannot see is shown as not visible, never guessed.</li>
            <li>When a scan falls behind it jumps to the head; skipped blocks are listed below as not scanned.</li>
          </ul></div>
        </div>
        <CoverageNotes model={model} />
      </section>
      </main>
      )}
      <footer className="foot">
        Drainer Watch is an automated, public monitor. Every claim links to its transaction; a tier is an assessment, not a verdict. Data: <a href="data.json">data.json</a>. Source and method: <a href="https://github.com/prettydeath/drainer-watch">github.com/prettydeath/drainer-watch</a>.
      </footer>
      {open ? <Boundary key={open.key} what="case file"><Suspense fallback={null}><CaseSpread c={open} model={model} onClose={close} onOpen={openCase} /></Suspense></Boundary> : null}
    </div>
  )
}
