// Human names and one-line explanations. Generated at build time from drainerwatch/template.html (scripts/vocab.mjs).
import vocab from '@/generated/vocab.json'
import type { Tier } from './types'

type Pair = [string, string]
const V = vocab as unknown as {
  TIERS: Record<Tier, Pair>
  LABELS: Record<string, Pair>
  FAMILIES: Record<string, Pair>
  ROLES: Record<string, Pair>
  VIA: Record<string, string>
  KIND: Record<string, string>
  SUBJ: Record<string, string>
  NATIVE: Record<string, string>
}

export const TIERS = V.TIERS
export const TIER_NAME: Record<Tier, string> = { T1: 'Confirmed', T2: 'Strong', T3: 'Suspect' }
export const TIER_BLURB: Record<Tier, string> = {
  T1: 'a drain is proven on chain',
  T2: 'strong evidence, short of proof',
  T3: 'fits a drainer, no confirmed drain yet',
}
export const TIER_ORDER: Tier[] = ['T1', 'T2', 'T3']
export const TIER_RANK: Record<string, number> = { T1: 1, T2: 2, T3: 3 }

const human = (k: string) => {
  const s = String(k).replace(/_/g, ' ')
  return s.charAt(0).toUpperCase() + s.slice(1)
}

export const labelInfo = (l: string): Pair =>
  V.LABELS[l] || [human(l), 'Detector label without a published description yet; see the method notes in the repository.']

export const famName = (f: string | null | undefined) =>
  !f ? 'Unattributed' : V.FAMILIES[f] ? V.FAMILIES[f][0] : /^f_/.test(f) ? 'Code family ' + f.slice(2) : human(f)

/** where a family's human name comes from (data.json family_name_source) */
export const FAM_SOURCE: Record<string, string> = {
  kit: 'kit', contract_name: 'self-named', token_name: 'named by its token', functions: 'named by its functions', hash: 'code hash only',
}
export const famSourceNote = (src: string | null | undefined) => (src ? FAM_SOURCE[src] || src.replace(/_/g, ' ') : null)
/** primary family label: family_name when the data has it (except a bare hash), else the vocab name of the hash */
export const famLabel = (hash: string | null | undefined, name?: string | null, src?: string | null) =>
  name && name.trim() && src !== 'hash' && name !== hash ? name.trim() : famName(hash)

export const famBlurb = (f: string | null | undefined) =>
  !f
    ? 'No kit fingerprint matched yet; grouped here until a family is found.'
    : V.FAMILIES[f]
      ? V.FAMILIES[f][1]
      : 'Contracts sharing one opcode skeleton or function set.'

export const roleInfo = (r: string | null | undefined): Pair => V.ROLES[r || ''] || [human(r || 'unknown'), 'Payout role.']
export const viaText = (v: string | null | undefined) => V.VIA[v || 'unknown'] || human(v || 'unknown')
export const kindText = (k: string) => V.KIND[k] || human(k)
export const nativeOf = (ch: string) => V.NATIVE[ch] || ch.toUpperCase()

export const CHAIN_SHORT: Record<string, string> = { eth: 'ETH', bsc: 'BSC', base: 'Base', tron: 'TRON' }
export const CHAIN_LONG: Record<string, string> = { eth: 'Ethereum', bsc: 'BNB Chain', base: 'Base', tron: 'TRON' }
export const chainShort = (c: string) => CHAIN_SHORT[c] || c.toUpperCase()
export const chainLong = (c: string) => CHAIN_LONG[c] || c.toUpperCase()

// labels that only a wallet (EOA) can carry: used when the code size was not looked up
export const EOA_LABELS = new Set([
  'eoa_spender_pull', 'eoa_spender_multi', 'emergency_gas', 'emergency_gas_self', 'emergency_gas_kit', 'oneshot_hub',
  'oneshot_multi', 'prefund_hub', 'prefund_multi', 'prefund_approve', 'prefund_approve_multi', 'operator_wallet',
  'operator_wallet_multi', 'serial_deployer', 'serial_deployer_multi', 'perm_hijack', 'perm_hijack_multi',
  'perm_hijack_drain', 'fixed_fee', 'fixed_fee_multi', 'foreign_recipient_swap', 'foreign_swap_multi', 'foreign_swap_kit',
  'batch_approval_drain', 'kit_router_swap', 'eip7702_operator', 'nft_operator_pull', 'batch7702_approve',
])

/* method axes for the kit profile (labels + evidence types) */
export const METHOD_AXES: [string, string[]][] = [
  ['Approve', ['approval_fingerprint', 'batch_approval_drain', 'kit_router_swap', 'eoa_spender_pull', 'eoa_spender_multi',
    'multi_victim_pull', 'approval_kit_shape', 'prefund_approve', 'prefund_approve_multi', 'approve_all_call',
    'aml_approve_transfer', 'increase_max', 'token_spender_pull', 'safe_spender_pull', 'vanity_drainer']],
  ['Permit', ['ms_deadline', 'ms_deadline_pull', 'deploy_drain']],
  ['Signed swap', ['foreign_recipient_swap', 'foreign_swap_multi', 'foreign_swap_kit', 'seaport_zero']],
  ['Bait payable', ['bait_payable', 'bait_withdraw', 'redflag_payable', 'kit_deposit', 'kit_exact', 'gen_back_transfer',
    'redflag_selectors', 'bait_forward', 'claimer_split']],
  ['Split payout', ['split_pull', 'split_xtx', 'pays_known_operator', 'fixed_fee', 'fixed_fee_multi', 'share_grid']],
  ['One-shot', ['oneshot_spender', 'oneshot_hub', 'oneshot_multi', 'prefund_hub', 'prefund_multi', 'owner_collect',
    'owner_gated_puller', 'kit_pull', 'ghost_forward']],
  ['7702', ['eip7702_sweeper', 'eip7702_operator', 'eip7702_batch', 'batch7702_approve']],
  ['Takeover', ['perm_hijack', 'perm_hijack_multi', 'perm_hijack_drain', 'owner_takeover']],
]
