// Smoke test: the app renders tests/fixtures/sample_data.json without throwing and opens a case from a deep link.
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import App from '@/App'
import { buildModel, search } from '@/lib/model'
import type { DataJson } from '@/lib/types'

const fixture = JSON.parse(readFileSync(resolve(import.meta.dirname, '../../../tests/fixtures/sample_data.json'), 'utf8')) as DataJson
const empty: DataJson = { generated_at: '', chains: {}, totals: { tiers: { T1: 0, T2: 0, T3: 0 }, victims_24h: 0, usd_24h: 0, usd_7d: 0, drains_24h: 0 }, contracts: [], drains: [], operators: [], families: [], deployers: [], vasps: [], daily: [], clusters: [] }

afterEach(() => { cleanup(); history.replaceState(null, '', '/') })

describe('app', () => {
  it('renders the fixture: headline, sections and case files', async () => {
    render(<App data={fixture} />)
    expect(screen.getByRole('heading', { level: 1 }).textContent).toMatch(/was taken from/)
    expect(screen.getByRole('heading', { name: 'Where the money went' })).toBeTruthy()
    expect(screen.getByRole('heading', { name: 'Case files' })).toBeTruthy()
    expect(document.querySelectorAll('[data-case-row]').length).toBeGreaterThan(0)
    expect(await screen.findByText(/Kits behind the drains/)).toBeTruthy()
  })

  it('opens the case spread from a card and from a deep link', async () => {
    render(<App data={fixture} />)
    const card = document.querySelector('[data-case-row]') as HTMLElement
    fireEvent.click(card)
    await waitFor(() => expect(document.querySelector('[data-case]')).toBeTruthy(), { timeout: 15000 })
    expect(location.hash).toBe('#' + card.dataset.caseRow)
    cleanup()
    const c = fixture.contracts[3]
    history.replaceState(null, '', '#' + c.chain + ':' + c.address)
    render(<App data={fixture} />)
    await waitFor(() => expect(document.querySelector('[data-case="' + c.chain + ':' + c.address + '"]')).toBeTruthy(), { timeout: 15000 })
    expect(screen.getByText('Why it is flagged')).toBeTruthy()
  })

  it('lists address poisoning apart from the case files', () => {
    const addr = '0x' + 'ab'.repeat(20)
    const data: DataJson = { ...fixture, totals: { ...fixture.totals, poisoning: 1 },
      poisoning: [{ chain: 'eth', address: addr, labels: ['spoof_split'], victims: 4, first_seen: '', last_seen: '',
        cluster: null, code_class: 'poisoner', contract_name: null }] }
    render(<App data={data} />)
    expect(screen.getByRole('heading', { name: 'Address poisoning' })).toBeTruthy()
    expect(document.querySelectorAll('#poisoning tbody tr').length).toBe(1)
  })

  it('renders empty data gracefully', () => {
    render(<App data={empty} />)
    expect(screen.getByRole('heading', { level: 1 }).textContent).toMatch(/No confirmed or strong drainer/)
    expect(screen.getByText(/No exchange deposit seen yet/)).toBeTruthy()
  })

  it('searches every address', () => {
    const m = buildModel(fixture)
    const payout = fixture.contracts[0].payouts[0].wallet
    expect(search(m, payout.slice(2, 14)).some(h => h.value === payout)).toBe(true)
  })
})
