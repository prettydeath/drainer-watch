import { useEffect, useState } from 'react'
import { addrUrl, arkhamUrl, hasExplorer, txUrl } from '@/lib/model'
import { mid } from '@/lib/format'

export const tv = (t: string | null | undefined) => (t ? 'var(--' + t.toLowerCase() + ')' : 'var(--flow)')

export function reduceMotion() {
  if (typeof window === 'undefined' || !window.matchMedia) return true
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches || new URLSearchParams(location.search).has('still')
}

export function useMedia(q: string) {
  const get = () => (typeof window !== 'undefined' && window.matchMedia ? window.matchMedia(q).matches : false)
  const [m, setM] = useState(get)
  useEffect(() => {
    if (!window.matchMedia) return
    const mq = window.matchMedia(q)
    const f = () => setM(mq.matches)
    mq.addEventListener('change', f)
    return () => mq.removeEventListener('change', f)
  }, [q])
  return m
}

function copyText(v: string) {
  try {
    navigator.clipboard?.writeText(v).catch(() => {})
  } catch {
    /* clipboard unavailable */
  }
}

/** Short identifier: click copies the full value; optional explorer link. */
export function Addr({ value, chain, h = 6, t = 4, link = false, className = '' }: {
  value: string | null | undefined; chain?: string; h?: number; t?: number; link?: boolean; className?: string
}) {
  const [copied, setCopied] = useState(false)
  if (!value) return <span className="muted">not visible</span>
  const copy = (e: React.MouseEvent) => {
    e.stopPropagation()
    copyText(value)
    setCopied(true)
    setTimeout(() => setCopied(false), 1200)
  }
  return (
    <span className={'addr ' + className}>
      <button type="button" className="mono addr-btn" title={value + ' (click to copy)'} aria-label={'Copy ' + value} onClick={copy}>
        {copied ? 'copied' : mid(value, h, t)}
      </button>
      {link && chain && hasExplorer(chain) ? (
        <a className="addr-ext" href={addrUrl(chain, value)} target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()} aria-label={'Open ' + value + ' in the explorer'}>↗</a>
      ) : null}
    </span>
  )
}

/** Full identifier with copy and explorer buttons (case spread). */
export function FullId({ value, chain, kind = 'address' }: { value: string | null | undefined; chain: string; kind?: 'address' | 'tx' }) {
  const [copied, setCopied] = useState(false)
  if (!value) return <span className="full muted">not visible</span>
  return (
    <span className="fullid">
      <span className="full" data-full={value}>{value}</span>
      <span className="fullid-tools">
        <button type="button" className="iconbtn" aria-label={'Copy ' + value} title="Copy" onClick={() => { copyText(value); setCopied(true); setTimeout(() => setCopied(false), 1200) }}>
          {copied ? 'copied' : 'copy'}
        </button>
        {hasExplorer(chain) ? (
          <a className="iconbtn" href={kind === 'tx' ? txUrl(chain, value) : addrUrl(chain, value)} target="_blank" rel="noopener noreferrer" aria-label={'Open ' + value + ' in the explorer'}>explorer ↗</a>
        ) : null}
        {kind === 'address' ? (
          <a className="iconbtn" href={arkhamUrl(value)} target="_blank" rel="noopener noreferrer" aria-label={'Open ' + value + ' in Arkham Intel'}>Arkham ↗</a>
        ) : null}
      </span>
    </span>
  )
}

export function Tx({ chain, tx, children }: { chain: string; tx: string | null | undefined; children?: React.ReactNode }) {
  if (!tx) return <span className="muted">not visible</span>
  if (!hasExplorer(chain)) return <span className="mono" title={tx}>{children || mid(tx, 8, 6)}</span>
  return (
    <a className={'txlink' + (children ? '' : ' mono')} href={txUrl(chain, tx)} target="_blank" rel="noopener noreferrer" title={tx} onClick={e => e.stopPropagation()}>
      {children || mid(tx, 8, 6)}
    </a>
  )
}

export function ThemeToggle({ theme, onToggle }: { theme: string; onToggle: () => void }) {
  return (
    <button type="button" onClick={onToggle} className="theme-toggle" aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'} title="Toggle theme">
      <svg width="16" height="16" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="6.25" fill="none" stroke="currentColor" strokeWidth="1.5" /><path d="M8 1.75a6.25 6.25 0 0 1 0 12.5z" fill="currentColor" /></svg>
    </button>
  )
}

function initialTheme(): 'light' | 'dark' {
  const q = new URLSearchParams(location.search).get('theme')
  if (q === 'dark' || q === 'light') return q
  try {
    const s = localStorage.getItem('dw-theme')
    if (s === 'dark' || s === 'light') return s
  } catch {
    /* storage blocked */
  }
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}
export function useTheme(): ['light' | 'dark', () => void] {
  const [theme, setTheme] = useState(initialTheme)
  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark')
    document.documentElement.dataset.theme = theme
  }, [theme])
  const toggle = () =>
    setTheme(t => {
      const n = t === 'dark' ? 'light' : 'dark'
      try { localStorage.setItem('dw-theme', n) } catch { /* storage blocked */ }
      return n
    })
  return [theme, toggle]
}
