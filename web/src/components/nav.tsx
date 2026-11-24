import { createContext, useContext } from 'react'

/** Opens a wallet case file (#wallet:chain:address) from anywhere in the app. */
export const WalletNav = createContext<((chain: string, address: string) => void) | null>(null)

/** Small "file" button next to a payout / recipient / holder address; renders nothing outside the app shell. */
export function WalletLink({ chain, address, label = 'file' }: { chain: string; address: string | null | undefined; label?: string }) {
  const open = useContext(WalletNav)
  if (!open || !address) return null
  return (
    <button type="button" className="linkbtn small wlink" data-wallet-link={chain + ':' + address}
      onClick={e => { e.stopPropagation(); open(chain, address) }} aria-label={'Open the wallet file of ' + address}>{label}</button>
  )
}
