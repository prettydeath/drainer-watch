// Data contract of site/data.json, produced by drainerwatch/render.py (build_payload). See SPEC.md.
export type Tier = 'T1' | 'T2' | 'T3'

export interface Gap { from: number; to: number; at: string }

export interface ChainInfo {
  cursor_block: number
  head_block: number
  lag_blocks: number
  last_scan_at: string
  explorer: string
  tx_path?: string
  native?: string | null
  block_sec?: number | null
  gaps?: Gap[]
  gap_blocks?: number
  note?: string
}

export interface Payout { wallet: string; role: string; share: number | null; txs: number | null }

export interface Deployer {
  address: string | null
  tx: string | null
  via: string
  factory: string | null
  block: number | null
  funder: string | null
  funder_entity: string | null
  funder_tx: string | null
  other_contracts: number
}

export interface VaspLink {
  subject: string
  role: string
  counterparty: string
  kind: string
  entity: string | null
  category: string | null
  tx: string | null
  tx_in: string | null
  ts: string
  amount: string | null
  symbol: string | null
  usd: number | null
  confidence: string | null
}

export interface Evidence { type: string; tx: string | null; ts: string; detail: string }

export interface Contract {
  chain: string
  address: string
  tier: Tier
  score: number
  source: string
  family: string | null
  labels: string[]
  first_seen: string
  last_seen: string
  victims: number
  drains: number
  usd: number
  code_size: number | null
  verified: boolean | null
  contract_name?: string | null
  /** human family label (backend >= family naming); `family` stays the code hash */
  family_name?: string | null
  family_name_source?: FamilyNameSource | null
  is_contract?: boolean | null
  payouts: Payout[]
  deployer: Deployer
  vasp_links: VaspLink[]
  evidence: Evidence[]
  cluster?: string | null
  cross_chain?: { chain: string; tier: Tier }[]
  /** approvals to this spender that are still open (backend >= allowance check) */
  open_allowances?: OpenAllowance[]
  /** the spender has executed any pull */
  pulled?: boolean | null
  /** Arkham Intel attribution of the subject, its payout wallets and largest victims (backend with ARKHAM_API_KEY) */
  arkham?: ArkhamAttribution[]
}

export interface ArkhamAttribution {
  address: string
  role: string
  entity: string | null
  entity_type: string | null
  label: string | null
  service: boolean | null
  deposit_service: string | null
}

export interface OpenAllowance {
  victim: string
  token: string
  symbol: string | null
  /** raw amount, or 'unlimited' */
  allowance: string | number | null
  victim_balance: string | number | null
  usd_at_risk: number | null
  pulled: boolean | null
  checked_at: string | number | null
}

export type FamilyNameSource = 'kit' | 'contract_name' | 'token_name' | 'functions' | 'hash'

export interface Drain {
  chain: string
  tx: string
  ts: string
  victim: string
  drainer: string
  token: string | null
  symbol: string | null
  amount: string | null
  usd: number | null
  recipient: string | null
}

export interface Vasp {
  entity: string
  category: string
  links: number
  usd: number
  subjects: number
  deposit_addresses: string[]
  chains: string[]
}

export interface Cluster {
  cluster: string
  chain: string
  members: string[]
  shared_wallets: string[]
  max_tier: Tier
  tiers: Partial<Record<Tier, number>>
}

export interface Totals {
  tiers: Record<Tier, number>
  victims_24h: number
  usd_24h: number
  usd_7d: number
  drains_24h: number
  drains_24h_all?: number
}

/** stablecoin balance on a drainer-linked address that the issuer can freeze (backend `freezable`) */
export interface Freezable {
  chain: string
  address: string
  role: string
  drainer: string
  drainer_tier: Tier | null
  token: string | null
  symbol: string | null
  issuer: string | null
  balance: string | number | null
  usd: number | null
  already_frozen: boolean | null
  checked_at: string | number | null
}

/** per-wallet aggregate from render.py (`wallets`), keyed "chain:address" */
export interface WalletDrainer { drainer: string; tier: Tier | null; role: string | null; share: number | null; usd: number; txs: number; first: string | null; last: string | null }
export interface WalletInflow { tx: string; ts: string; victim: string; drainer: string; token: string | null; symbol: string | null; amount: string | null; usd: number | null }
export interface WalletOutflow { counterparty: string; kind: string; entity: string | null; category: string | null; tx: string | null; tx_in: string | null; ts: string; amount: string | null; symbol: string | null; usd: number | null; confidence: string | null }
export interface WalletAgg {
  roles: string[]
  drainers: WalletDrainer[]
  inflows: WalletInflow[]
  outflows_known: WalletOutflow[]
  first_in: string | null
  last_in: string | null
  total_in_usd: number
  n_in: number
}

export interface DataJson {
  generated_at: string
  chains: Record<string, ChainInfo>
  totals: Totals
  contracts: Contract[]
  drains: Drain[]
  operators: { chain: string; wallet: string; drainers: number; affiliates: number; usd: number }[]
  families: { family: string; members: number; seed_members: number; chains: string[]; family_name?: string | null; family_name_source?: FamilyNameSource | null }[]
  deployers: { chain: string; address: string; contracts: number; funder_entity: string | null }[]
  vasps: Vasp[]
  daily: { date: string; usd: number; victims: number; new_contracts: number }[]
  clusters: Cluster[]
  /** absent in data.json produced before the freezable check existed */
  freezable?: Freezable[]
  freezable_total?: Record<string, number>
  /** USD still pullable through open approvals, all subjects */
  exposure_total_usd?: number | null
  wallets?: Record<string, WalletAgg>
}
