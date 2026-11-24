# drainer-watch — MVP spec (P0)

Real-time-ish monitor of crypto drainer contracts on ETH / BSC / Base, published as a static
dashboard (GitHub Actions + Pages), same pattern as `C:\Claude code\usdt-freeze-watch`
(package `freezewatch`: requests-only, sqlite in `data/`, `template.html` -> `site/index.html`).
Read that project first and mirror its conventions (util.http_json retries, key_pool, meta cursor,
write_if_changed, logging style).

Honesty rules: every flagged address carries evidence (tx hashes) and a tier; never invent data;
detectors must be explainable rule-by-rule. Full addresses/tx hashes everywhere (no truncation in data).

## Layout
```
drainer-watch/
  drainerwatch/  __init__ __main__ cli constants util db rpc seeds scan detectors bytecode
                 tokens prices enrich alerts render template.html
  tests/         unit tests (synthetic logs/blocks), fixtures/sample_data.json
  data/          drainerwatch.sqlite (gitignored on main), contracts.csv, drains.csv
  site/          index.html (rendered), data.json
  .github/workflows/ ci.yml, watch.yml (cron */10, data branch), pages.yml
  pyproject.toml README.md (English) LICENSE (MIT) .gitignore
```
Deps: `requests`, `pycryptodome` (keccak for selectors/topics). Python >=3.11.

## Sources
- RPC (env override `ETH_RPC_URL`, `BSC_RPC_URL`, `BASE_RPC_URL`), defaults
  `https://ethereum-rpc.publicnode.com`, `https://bsc-rpc.publicnode.com`, `https://base-rpc.publicnode.com`
  (verified: all support `eth_getBlockReceipts`, JSON-RPC batch).
- Seeds: ScamSniffer `https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json`
  (JSON list of ~2.5k lowercase addresses, chain-agnostic) + local `data/seeds.csv`
  (`chain,address,label,source`) for operator-supplied seeds. Refresh at most once per 6 h.
- Optional keyed enrichment: Etherscan V2 (`ETHERSCAN_API_KEYS`, comma list, chainid 1/56/8453) —
  best-effort only (free tier may not cover BSC/Base; failure must not break the run).
- Prices: CoinGecko simple price (keyless) for ETH, BNB; stablecoins = 1.0. Other tokens: amount only, usd=null.

## Ingestion (per chain, incremental cursor in `meta`)
- First run starts at `latest - initial_blocks` (default 300). Each run processes up to
  `--max-blocks` (default eth 100, base 400, bsc 800) within `--budget-sec`; lag is reported, not hidden.
- All chains: `eth_getLogs` for topic0 ∈ {Transfer, Approval} over adaptive block chunks
  (halve on "too many results"/timeout). Transfer with 3 topics = ERC-20 (ignore 4-topic ERC-721 in MVP,
  but count `ApprovalForAll` (topic0) to seed operators).
- ETH only (light enough): `eth_getBlockByNumber(full=true)` for each block -> type-0x4 txs
  (`authorizationList`), top-level contract creations (to == null; address from receipt), and
  `value>0` calls whose 4-byte selector is in the red-flag set.
- Tx lookups (`eth_getTransactionByHash`) ONLY for candidate txs produced by detectors (to learn tx.from / tx.to).
- `eth_getCode` cached in db (addr -> code hash, size, is_contract).

## Detectors (each emits `evidence` rows: type, chain, address, tx, detail JSON)
- D1 `seed_activity`: Approval/ApprovalForAll where spender ∈ seeds, or Transfer to ∈ seeds -> victim event.
  Seed address with observed activity => contract row, source=`scamsniffer`/`local`.
- D2 `split_pull` (core): within one tx, ≥2 Transfer logs of the same token, same `from` (=victim),
  to ≥2 distinct recipients, largest share in [0.60, 0.95]; then fetch tx: require tx.from != victim and
  tx.to not in ALLOWLIST (CoW GPv2Settlement, UniswapX reactors, 1inch v5/v6 routers, 0x settler(s),
  Uniswap Universal Router, Safe singletons/multisend — put the list in constants with sources noted).
  drainer = tx.to; recipients -> payout wallets (role operator = smaller share, affiliate = larger share;
  label "inferred" — this matches DaaS fee splits).
- D3 `multi_victim_pull`: tx.to (not allowlisted) caused Transfer from ≥3 distinct non-sender addresses
  within the rolling 24 h window (across runs, via db). Candidate generation: Transfer.from != tx.from
  requires tx lookup — limit lookups to txs whose Transfer.from had an Approval to the same tx.to seen in
  the last 7 days in our db, OR whose recipient is a known payout wallet.
- D4 `pays_known_operator`: address whose outgoing token transfers reach a known operator/payout wallet
  (seed or inferred) in ≥2 distinct txs.
- D5 `bytecode` (bytecode.py): skeleton hash = opcode stream with PUSH immediates zeroed and trailing
  solidity CBOR metadata stripped -> sha256; selector set = PUSH4 values followed by EQ/JUMPI pattern.
  Red-flag selectors (compute keccak at import): `Claim()`, `claim()`? NO — only capitalised kit names:
  `Claim()`, `ClaimReward()`, `ClaimRewards()`, `SecurityUpdate()`, `Connect()`, `Execute()`, `Multicall()`,
  `NetworkMerge()`, `ClaimAirdrop()`. Skeleton/selector-Jaccard (≥0.8) match against skeletons of seed
  contracts (lazily fetch code for seeds that are contracts on that chain, ≤100 per run, cached) => family id.
  Applied to: top-level creations (ETH), every D2/D3/D4 drainer, every 7702 delegate.
- D6 `eip7702_sweeper` (ETH): per delegate address count authorizations; fetch delegate code; heuristic
  sweeper = code size < 1024 and contains CALLVALUE + PUSH20 + CALL and no SLOAD-gated owner check
  (best-effort) OR delegate ∈ seeds. Record delegators as potential victims.
- D7 `redflag_payable` (ETH): value>0 tx to contract with red-flag selector -> evidence; native forwarding
  not visible without traces (note this in README "limitations"); optional Etherscan txlistinternal for
  such contracts to detect native split ratio.

## Kit rules (private kit notes)
- MS Drainer S1-S4 / VerifyAccount R-A1..R-A4: D7 `bait_payable`, D9 `approval_fingerprint`, D10
  `foreign_recipient_swap`, `split_xtx`, `owner_gated_puller`, `kit_signature`, clusters (see README table).
- kit notes K1-K14 (EVM): K1 MS_NEW 5-arg bait (`ms_new`, roles customer/worker); K2 generated bait
  (`ms_generated`, exact runtime keccak `kit_exact`, storage receivers, `gen_back_transfer`); K3 pass-through variant;
  K4 `ms_deadline` (permit/Permit2 deadline in [1e12, 1e13]); K5/K12 `oneshot_spender` (nonce <= 3 pull, hub fund /
  25 200-gas return); K6 `kit_deposit`; K7 `batch_approval_drain`; K8 `kit_router_swap` + V3 exactInputSingle decode;
  K9 `owner_collect` / `owner_collector`; K13 `eip7702_operator` (boost); K14 `cross_chain` (+ `enrich.cross_chain_check`).
  kit notes N1-N11: N1 `ms_cashback`; N2 family `trusty_v1` + `kit_public` (exact runtime); N3 `kit_confirmed`
  (watchlist `KIT_PUBLIC_CONTRACTS`; Base via per-tx lookup of txs to those addresses); N4 `dust_approve`; N5
  `emergency_gas`; N6 ETH-in V2 swaps in D10; N7 `kit_router_swap` across txs (<= 300 s, same run); N8 gas 30 000 (K5) /
  150 000 (K6); N9 `kit_vanity` (boost); N10 covered by R-A1; N11 detail only.
  TRON K10/K11 pending. Tiers in `detectors.assign_tier`. Calldata/gas/nonce rules (K1-K8) run in the ETH full-block
  pass only; K9 needs the receipts source.

## Deployer & VASP links (operator request — first-class feature)
- Labels: wallet-attribution dataset (public, MIT) — raw
  `https://raw.githubusercontent.com/prettydeath/wallet-attribution/main/data/{ethereum,bsc,base}.csv`
  (local fallback `C:\Claude code\wallet-attribution\data\*.csv` via env `WA_DATA_DIR`), columns
  `address,network,entity,label,category,...`. Keep categories exchange, instant-exchange/service, bridge,
  mixer, sanctioned, gambling, payment (treat `exchange` as VASP; others shown with their category).
  Load into table `labels(chain,address,entity,label,category)`, refresh ≤ once/24 h.
- Deployer (enrich.py, for every T1/T2 contract, cached, ≤50 lookups/run):
  1) top-level creations: deployer = tx.from (already known);
  2) else Etherscan V2 `module=contract&action=getcontractcreation` (contractCreator, txHash);
  3) else unknown (do NOT guess). For CREATE2 children also record `factory` (the creator contract) and
     the factory's own deployer if resolvable.
  Then deployer funding: first incoming native tx to deployer (Etherscan `txlist` sort=asc page=1 offset=5,
  and `txlistinternal`) -> `funder`, with label from `labels` if any (e.g. "FixedFloat", "Binance").
- VASP flow links (passive, from logs we already scan + db): for drainer, payout wallets, deployer:
  a) direct: Transfer to an address in `labels` -> link(kind=direct, entity, category, tx, amount, usd);
  b) deposit-address heuristic: X receives from drainer/payout wallet, and within 72 h X forwards to an
     exchange-labelled hot wallet -> X = probable deposit address of that entity (kind=deposit_sweep,
     confidence medium, both txs as evidence);
  c) funding: deployer funder labelled -> link(kind=funding).
  Optional on-demand 1–2 hop forward walk for T1 payout wallets via Etherscan `tokentx` (≤20 calls/run).
- Table `vasp_links(chain,subject,subject_role[drainer|payout|deployer],counterparty,kind,entity,category,
  tx,ts,amount,usd,confidence, UNIQUE(chain,subject,counterparty,kind,tx))`.
- Per-entity aggregate in data.json for law-enforcement use (where to send VASP requests).

## Tiers / score
- T1 confirmed: seed with observed activity, OR D2 with ≥3 distinct victims, OR D2 + family match.
- T2 strong: D2 with 1–2 victims, D4, family match to seed (D5) with any activity.
- T3 suspect: D3 alone, D6 heuristic, D7 alone, red-flag selectors alone.
- score 0–100 = documented additive weights in constants; tier is the published field.
- False-positive guards: ALLOWLIST, ignore victims that are contracts (except 7702-delegated EOAs),
  min transfer usd 1 where price known; verified-source cap and unpriced single-victim split cap (`unpriced_capped`).

## DB (sqlite)
contracts(chain,address,tier,score,source,family,labels JSON,first_seen,last_seen,victims,drains,usd,
code_hash,code_size,is_contract,verified NULL/0/1, PRIMARY KEY(chain,address))
evidence(id,chain,address,type,tx,block,ts,detail JSON, UNIQUE(chain,address,type,tx))
drains(chain,tx,log_index,ts,victim,drainer,token,symbol,decimals,amount,usd,recipient, UNIQUE(chain,tx,log_index))
payouts(chain,drainer,wallet,role,share,txs, PRIMARY KEY(chain,drainer,wallet))
approvals(chain,owner,spender,token,tx,block,ts)  -- rolling 7 d, pruned
tokens(chain,address,symbol,decimals) · codes(chain,address,code_hash,size,skeleton,selectors JSON)
seeds(address,chain NULL,label,source,added) · meta(k,v)

## CLI
`drainerwatch run [--chains eth,bsc,base] [--max-blocks N] [--budget-sec S]` (scan + detect + render)
`drainerwatch loop --interval 60` (for a Linux box) · `drainerwatch render` · `drainerwatch seeds`
`drainerwatch backtest --chain eth --from-block A --to-block B` (no cursor change)
Alerts (alerts.py): Telegram if `TELEGRAM_BOT_TOKEN`+`TELEGRAM_CHAT_ID` set, on new T1/T2 only; else no-op.

## Data contract: `site/data.json` (also embedded into index.html at `/*__DATA__*/null`)
```json
{
  "generated_at": "2026-11-23T10:00:00Z",
  "chains": {"eth": {"cursor_block": 0, "head_block": 0, "lag_blocks": 0, "last_scan_at": "", "explorer": "https://etherscan.io"}},
  "totals": {"tiers": {"T1": 0, "T2": 0, "T3": 0}, "victims_24h": 0, "usd_24h": 0, "usd_7d": 0, "drains_24h": 0},
  "contracts": [{"chain": "eth", "address": "0x…", "tier": "T1", "score": 90, "source": "detector|scamsniffer|local",
                 "family": "f_ab12cd or null", "labels": ["split_pull", "seed"], "first_seen": "", "last_seen": "",
                 "victims": 0, "drains": 0, "usd": 0, "code_size": 0, "verified": null,
                 "payouts": [{"wallet": "0x…", "role": "operator|affiliate", "share": 0.2, "txs": 0}],
                 "deployer": {"address": "0x… or null", "tx": "0x…", "via": "toplevel|etherscan|unknown",
                              "factory": "0x… or null", "funder": "0x… or null", "funder_entity": "FixedFloat or null",
                              "funder_tx": "0x…", "other_contracts": 0},
                 "vasp_links": [{"subject": "0x…", "role": "drainer|payout|deployer", "counterparty": "0x…",
                                 "kind": "direct|deposit_sweep|funding", "entity": "Binance", "category": "exchange",
                                 "tx": "0x…", "ts": "", "amount": "1.0", "symbol": "USDT", "usd": 1.0,
                                 "confidence": "high|medium"}],
                 "evidence": [{"type": "split_pull", "tx": "0x…", "ts": "", "detail": "human readable"}],
                 "cluster": "op_ab12cd34ef or null",
                 "cross_chain": [{"chain": "bsc", "tier": "T2"}]}],
  "drains": [{"chain": "eth", "tx": "0x…", "ts": "", "victim": "0x…", "drainer": "0x…", "token": "0x…",
              "symbol": "USDT", "amount": "123.45", "usd": 123.45, "recipient": "0x…"}],
  "operators": [{"chain": "eth", "wallet": "0x…", "drainers": 0, "affiliates": 0, "usd": 0}],
  "families": [{"family": "f_ab12cd", "members": 0, "seed_members": 0, "chains": ["eth"]}],
  "deployers": [{"chain": "eth", "address": "0x…", "contracts": 0, "funder_entity": null}],
  "vasps": [{"entity": "Binance", "category": "exchange", "links": 0, "usd": 0, "subjects": 0,
             "deposit_addresses": ["0x…"], "chains": ["eth"]}],
  "daily": [{"date": "2026-11-23", "usd": 0, "victims": 0, "new_contracts": 0}],
  "clusters": [{"cluster": "op_ab12cd34ef", "chain": "eth", "members": ["0x…"], "shared_wallets": ["0x…"],
                "max_tier": "T1", "tiers": {"T1": 1, "T3": 1}}]
}
```
Limits: contracts ≤ 2000 (sorted tier, last_seen desc), drains last 500, evidence ≤ 20 per contract.

## Dashboard (template.html, single file, no external JS/CSS CDNs, English)
Analyst-console style like freezewatch: KPI strip (T1/T2/T3, victims 24h, USD 24h/7d, chain lag),
filterable/sortable contracts table (chain, tier, labels, search by address), detail drawer per contract
(evidence txs with explorer links, payout split bar, family, first/last seen, DEPLOYER block: address,
creation tx, factory, funder + funder entity, other contracts by same deployer; VASP LINKS block: table of
entity/category/kind/counterparty/tx/amount/confidence), deployer column in main table, live drains feed,
operators table, families table, "VASP exposure" table (entity, links, USD, deposit addresses — the
"where to send requests" view), deployers table, daily inline-SVG bar chart, light/dark (prefers-color-scheme + toggle),
works at 375 px width, copy-address buttons, "Limitations & method" section explaining tiers.
Must render correctly with empty arrays and with `tests/fixtures/sample_data.json`.
