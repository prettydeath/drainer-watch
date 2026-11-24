const nf0 = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 })

export const fmtUSD = (n: number | null | undefined, compact = false) =>
  n == null
    ? 'unpriced'
    : compact && Math.abs(n) >= 1000
      ? '$' + (Math.abs(n) >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : (n / 1000).toFixed(n >= 10000 ? 0 : 1) + 'k')
      : '$' + nf0.format(n)
export const fmtInt = (n: number | null | undefined) => nf0.format(n || 0)

export const H = 3600e3
export const DAY = 24 * H

/** ISO string, epoch milliseconds, or epoch seconds (some backend fields, e.g. checked_at) -> epoch ms */
export const toMs = (ts: string | number | null | undefined): number =>
  ts == null || ts === '' ? NaN : typeof ts === 'number' ? (Math.abs(ts) < 1e11 ? ts * 1000 : ts) : /^\d+(\.\d+)?$/.test(ts) ? toMs(Number(ts)) : Date.parse(ts)

export function ago(ts: string | number, now = Date.now()) {
  const t = toMs(ts)
  if (!Number.isFinite(t)) return 'unknown'
  const s = (now - t) / 1000
  if (s < 90) return 'just now'
  if (s < 3600) return Math.round(s / 60) + ' min ago'
  if (s < 86400) return Math.round(s / 3600) + ' h ago'
  return Math.round(s / 86400) + ' d ago'
}
const valid = (ts: string | number) => Number.isFinite(toMs(ts))
export const fmtDay = (ts: string | number) =>
  valid(ts) ? new Date(toMs(ts)).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', timeZone: 'UTC' }) : 'unknown date'
export const fmtTime = (ts: string | number) =>
  valid(ts) ? new Date(toMs(ts)).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', timeZone: 'UTC' }) : ''
export const fmtStamp = (ts: string | number) => (valid(ts) ? fmtDay(ts) + ', ' + fmtTime(ts) + ' UTC' : 'unknown time')

export const mid = (a: string | null | undefined, h = 6, t = 4) =>
  !a ? '' : a.length <= h + t + 1 ? a : a.slice(0, h) + '…' + a.slice(-t)

export const plural = (n: number, one: string, many = one + 's') => fmtInt(n) + ' ' + (n === 1 ? one : many)
