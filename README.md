# drainer-watch

Near-real-time monitor of crypto **drainer contracts** on Ethereum, BNB Chain and Base, published as a static
dashboard (GitHub Actions cron + GitHub Pages). Every flagged address carries evidence (tx hashes), a tier and the
rule that fired. It also links drainers, payout wallets and deployers to **VASPs** (exchanges, instant exchangers,
bridges, mixers) so that requests can be sent to the right entity.

Same pattern as [usdt-freeze-watch](../usdt-freeze-watch): `requests` + `pycryptodome` only, sqlite in `data/`,
state kept on an orphan `data` branch, dashboard rendered from `drainerwatch/template.html`.

## Run

```bash
pip install requests pycryptodome
python -m drainerwatch run --chains eth,base,bsc --max-blocks 30 --budget-sec 300
python -m drainerwatch loop --interval 60          # for a Linux box
python -m drainerwatch render                      # data/*.sqlite -> site/index.html + site/data.json
python -m drainerwatch seeds                       # refresh seeds, print counts
python -m drainerwatch backtest --chain eth --from-block 21000000 --to-block 21000200   # separate db, no cursor change
python -m drainerwatch run --chains eth --source logs       # force eth_getLogs (default: receipts on eth/base, logs on bsc)
python -m drainerwatch incidents --env-file ~/.claude/secrets/osint.env          # rebuild tests/backtest/incidents.csv
python -m drainerwatch backtest --incidents tests/backtest/incidents.csv --split dev --blind   # blind incident backtest
pytest -q
```

Environment (all optional): `ETH_RPC_URL`, `BSC_RPC_URL`, `BASE_RPC_URL` (default publicnode),
`ETHERSCAN_API_KEYS` (comma list, Etherscan V2), `WA_DATA_DIR` (local wallet-attribution CSVs),
`TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` (alerts on new T1/T2; no-op without them), `DASHBOARD_URL`.

Operator inputs in `data/`: `seeds.csv` (`chain,address,label,source`), `allowlist.csv` (`chain,address,note`).

Actions: add secrets `ETHERSCAN_API_KEYS` (and optionally the Telegram/RPC ones), enable Pages with source
"GitHub Actions". `watch.yml` runs every 10 minutes and force-pushes `data/` + `site/` to the `data` branch.

## Detectors

| id | rule | tier effect |
|----|------|-------------|
| D1 `seed_activity` | approval / ApprovalForAll to a seed, or a token transfer to a seed (ScamSniffer + `seeds.csv`) | seed with activity = T1 |
| D2 `split_pull` | one tx, one token, one `from`, 2+ recipients, largest share 60-95 %, `tx.from != victim`, `tx.to` a non-allowlisted contract, victim an EOA | 3+ victims or family match = T1, else T2 |
| D3 `multi_victim_pull` | one non-allowlisted contract pulls from 3+ approving wallets within 24 h | T3 |
| D4 `pays_known_operator` | a contract pays a known operator/payout wallet in 2+ txs | T2 |
| D5 bytecode | opcode skeleton (PUSH data zeroed, CBOR metadata stripped), PUSH4/EQ selector set, red-flag selectors (`Claim()`, `SecurityUpdate()`, ...), family = skeleton or selector Jaccard >= 0.8 against seed bytecode | family + activity = T2, otherwise T3 |
| D6 `eip7702_sweeper` (ETH) | type-4 delegate that is a seed or a small CALLVALUE+PUSH20+CALL contract without SLOAD; delegators are recovered by ecrecover | T3 |
| D7 `redflag_payable` (ETH) | value > 0 call with a red-flag selector | T3 |
| D7 `bait_payable` (ETH) | value > 0 successful call to an MS-Drainer-style `bait(address)` function (`Claim(address)`, `SecurityUpdate(address)`, ... `MS Drainer kit notes` S1) present in the contract dispatcher; the argument (not the sender, not the contract) is the kit **customer** payout wallet (payouts role `customer`); `withdraw(address)` / `withdraw(address,uint256)` callers of a bait contract are customers too (`bait_withdraw`) | 3+ distinct paying victims = T1, else T2 |
| D8 `eoa_spender_pull` (receipts source) | an EOA pulls another EOA's tokens directly (`token.transferFrom`, Permit2 signature transfer, or through its own EIP-7702-delegated account) to a third EOA; victim nonce >= 3 (not a custodial deposit address), spender nonce < 2000 (not a high-volume sweeper), no legitimate label on spender/recipient/victim. The recipient is stored as payout role `collector` | 3+ victims in 24 h = T2, else T3 |
| D9 `approval_fingerprint` | ERC-20 `Approval` whose amount equals a kit-hard-coded value (`constants.KIT_APPROVAL_AMOUNTS`, fingerprint table; MS Drainer `0xb88e282822ab5ed106947c1c60af583c1741a38e858de00000`); spender flagged, owner = victim | T1 (kit-confirmed) |
| D10 `foreign_recipient_swap` (ETH) | victim-signed V2-router `swapExactTokensFor{ETH,Tokens}[SupportingFeeOnTransferTokens]` or SwapRouter02 `multicall(deadline, bytes[])` with inner `swapExactTokensForTokens`, `amountOutMin == 0`, `to != tx.from`, recipient an EOA, tx succeeded; the recipient is the subject ("drainer receiver") | 3+ victims in 24 h (`foreign_swap_multi`) AND deadline = block time + 99 990 s +/- 900 (`foreign_swap_kit`) = T1; one of them = T2; else T3 |
| R-A1 `split_xtx` (receipts source) | same caller + same victim + same token, 2+ pulls in different txs within 60 s (same block or a straddled chunk boundary) to 2+ recipients, largest share 60-99 % (the TRON VerifyAccount family splits 98/2 in two txs); subject = `tx.to` puller contract, or the caller when it calls the token / Permit2 itself; victim EOA with nonce >= 3. The in-tx D2 bound stays 95 % | 3+ victims = T1, 2 = T2, 1 = T3 |
| R-A2 `owner_gated_puller` | static: small non-token contract (<= 6 KB, <= 10 selectors) with an owner check (CALLER compared with SLOAD), an external `transferFrom` (PUSH4 `0x23b872dd` not in the dispatcher) + CALL, and no hard-coded address (no PUSH20 other than the 0xff..ff mask, no address-like PUSH32 immutable) | T3; T2 with any behavioural evidence |
| S1 / R-A3 `kit_signature` | dispatcher fingerprint: `ms_drainer` = 1+ bait(address) + 2+ companion selectors (`getOwner()`, `getBalance()`, `getUserBalance(address)`, `getWithdrawStatus(address)`, `setWithdrawStatus(bool)`, `withdraw(address)`, `withdraw(address,uint256)`); `verify_account` = 2+ of `Verify20` 0x5082dd12, `Verify10` 0xfc61dd23, `withdrawAllTrxTo` 0xea4418d9. Shown as `family` | T2 with activity, else T3 |
| K1 `bait_payable` kit `ms_new` (ETH) | MS_NEW public contract: family `ms_new` = 3+ of the 19 five-arg baits `(depositer, handler, keeper, uint8 percent, bool)` + 2+ companions (`changePercentage`, `claimSalary`, `disableSalary`, `enableSalary`, `salaryStatus`, `setReceiver`); value > 0 call strictly decoded (percent <= 99, bool), handler = payout `customer`, keeper = payout `worker` | as D7: 3+ victims T1, else T2 |
| K2 `ms_generated` / `kit_exact` (ETH) | Contract Generator bait: exact keccak of the 16 kit runtimes (`kit_exact`) or traits (850-950 B, one PUSH4 = one of 16 no-arg bait names, PUSH2 0x08fc x2, PUSH1 0x64, 2+ CALL, no SSTORE); victim call -> `bait_payable` with receivers read from storage (`customer` / `kit_fee`, percent), `fresh` (created <= 1 h before), reuse count; deployer leftover transfer -> `gen_back_transfer` (`kit_wallet`) | kit_exact T2; bait as D7; back transfer T3 |
| K3 pass-through (ETH) | `ms_drainer` fingerprint without SSTORE in the runtime = variant `passthrough`; `bait_payable` gets `passthrough` and `balance_neutral` (archive balance before/after) | as D7 |
| K4 `ms_deadline` (ETH) | permit 0xd505accf / DAI 0x8fcbaf0c / Permit2 single 0x2b67b570 / batch 0x2a2d80d1 calldata with deadline / expiry / expiration / sigDeadline in [1e12, 1e13] (milliseconds); subject = spender, owner = victim, self-submitted permits ignored | T1 with a pull (same chunk `ms_deadline_pull`, or any pull label), else T2 |
| K5 / K12 `oneshot_spender` (ETH) | EOA with tx nonce <= 3 pulls a third party's tokens (transferFrom / Permit2), linked to the hub that funded it <= 30 blocks before (K12) and/or received its leftover with gasLimit exactly 25 200 <= 50 blocks after (K5); subject = hub, payouts `worker` | 3+ workers with a 25 200 return = T1 (`oneshot_multi`); a return = T2 (`oneshot_hub`); fund-only 3+ = T2 (`prefund_multi`), 1-2 = T3 (`prefund_hub`) |
| K6 `kit_deposit` (ETH) | MS_NEW `Deposit` 0x38928522 from an EOA with nonce <= 2, gasLimit in {100 000, 5 000 000, 900 000}, value >= 90 % of its balance | T2 |
| K7 `batch_approval_drain` | one tx: 2+ Approvals of one owner with the kit amount or uint256 max, tokens leave the owner, nothing comes back, an EOA receives them; subject = that EOA | T1 |
| K8 `kit_router_swap` | one tx: kit-amount Approval to a legitimate router + the same drain shape (V3 exactInputSingle fee / deadline / amountOutMinimum kept as detail). D10 also accepts V3 exactInputSingle with fee 3000 and deadline +300 s (`v3_kit_shape`) | T1 (D10 shape alone T3) |
| K9 `owner_collect` + family `owner_collector` (receipts source) | dispatcher with 5+ of `collectToOwner` 0xd253abea, `collectAllFrom` 0x130cbae0, `permitAndCollect` 0x889d79b0, `rescueToken` 0xe5711e8b, `setOwner` 0x13af4035, `owner` 0x8da5cb5b; behaviour: caller pulls a third party's tokens through it to itself (also for R-A2 pullers); payout `collector` | T2; 3+ victims T1 |
| K13 `eip7702_operator` | K5 hub or K9 caller is an EIP-7702-delegated EOA | score boost only |
| K14 `cross_chain` | same address + same skeleton flagged on 2+ chains (and `enrich.cross_chain_check` for T1/T2 contracts on the other chains, <= 40 code lookups per run); `cross_chain` list in data.json | twin of a T1 = T2 (`cross_chain_t1`), else T3 |
| R-A4 clusters | flagged subjects sharing a payout wallet (split payout, D8 collector or MS customer) form one `operator_cluster` (`cluster` on contracts, `clusters` list in data.json). A member inherits the cluster's best own tier (`cluster_inherited`) only if both it and the better member have behavioural (non-bytecode) evidence and the link is not a single weak one (2+ shared wallets or 2+ payout txs, not customer-only) | inheritance as described |

`data.json` per contract also carries payout wallets (operator/affiliate split is **inferred** from the shares;
kit roles `customer`, `worker`, `collector`, `kit_fee`, `kit_wallet`, `submitter`), the deployer block, the VASP
links and `cross_chain` twins. Kit signatures come from static study of drainer kits (MS Drainer
variants, the TRON VerifyAccount family and others); the research notes and real-data kit regressions are kept private.

## Deployer and VASP links

* Labels: [wallet-attribution](https://github.com/prettydeath/wallet-attribution) CSVs, refreshed every 24 h.
* Deployer: top-level creation seen on ETH (`tx.from`), else Etherscan `getcontractcreation` (`tx.from` of the creation
  tx; a creating contract is recorded as `factory`), else **unknown. A deployer is never guessed.**
  Funder = first incoming native transfer to the deployer (Etherscan `txlist`/`txlistinternal`).
* Links: `direct` (transfer to a labelled wallet, high), `deposit_sweep` (an address that received from a drainer or
  payout wallet and forwarded to an exchange-labelled wallet within 72 h: probable deposit address, **medium**, both
  txs kept), `funding` (labelled funder of the deployer, high). `vasps[]` aggregates per entity for requests.

## Method & limitations

* **Backtest (2026-11-23).** `tests/backtest/` holds a blind backtest on 202 real ETH incidents (74 ScamSniffer /
  wallet-attribution seeds, 2025-01 .. 2026-11) split by seed component into dev/holdout; see `report_dev_*.md`,
  `report_holdout_*.md`. In that set almost every drain is a **single-recipient pull** (an operator EOA calling
  `transferFrom`, or an operator's 7702 account); DaaS-style split pulls (D2) did not occur. Before D8 the blind recall
  was 0 % on both splits. Recall at T1/T2 remains low; most D8 hits are T3 leads because custodial sweepers (exchanges,
  payment gateways) produce the same on-chain shape (hundreds per 120 blocks before the nonce filters).
* **Block source.** Default per chain (`constants.CHAINS[..]["source"]`): **receipts on ETH and Base, logs on BSC**;
  `--source` / `DRAINERWATCH_SOURCE` override all chains. `eth_getBlockReceipts` gives logs plus from/to of every tx (no
  tx lookups, works on historical blocks where publicnode refuses archive getLogs) and enables D8 and R-A1. Measured
  2026-11-23 on 20 recent blocks per chain (incl. the ETH full-block pass), logs vs receipts: ETH 23.0 vs 37.1 MB,
  7.5 vs 14.2 s, and the logs path hit the 400 tx-lookup cap inside those 20 blocks (candidates silently dropped);
  Base 0.6 vs 2.7 MB, 0.6 vs 1.2 s; BSC 4.0 vs 10.7 MB but 1.4 vs 22.9 s (856 code + 355 nonce lookups for D8), i.e.
  ~15 min for the default 800 BSC blocks per run, beyond the 300 s budget, so BSC stays on logs (no D8 / R-A1 there).

* **No traces.** Everything comes from logs and top-level transactions. Factory/CREATE2 (internal) creations are not visible
  on any chain, contract creations are scanned on ETH only (none on BSC/Base), and native-coin internal splits are
  not visible; native drains are therefore under-counted. Only ERC-20 `Transfer`
  legs are analysed; ERC-721/1155 are ignored (ApprovalForAll is used only to match seeds).
* **Public RPC.** publicnode currently refuses address-less multi-block `eth_getLogs`; the client falls back to one
  `getLogs` per block inside JSON-RPC batches. Backlog is reported as `lag_blocks` per chain, not hidden. The ETH full
  block pass (type-4, creations, red-flag payable) runs on ETH only; at most 400 creations per run are analysed.
* **Approvals** are stored only for spenders that are seeds / known drainers / approved by 3+ owners in a block chunk,
  never allowlisted, kept 7 days (D3 candidate generation). Tx lookups and code lookups are capped per chunk.
* **False-positive guards.** Allowlist of routers/settlers/Safe/4337 EntryPoints (`constants.ALLOWLIST`, extend in
  `data/allowlist.csv`), wallet-attribution `defi/mev/exchange/bridge` labels, contract victims are ignored (except
  7702-delegated EOAs), transfers below 1 USD ignored where a price is known, fake lookalike tokens (non-ASCII or
  within one edit of USDT/USDC/... on a non-canonical contract) are treated as address poisoning and skipped.
  USD is only known for stablecoins/wrapped natives by address; other tokens show amount only.
* **Tiers.** T1 confirmed (seed with activity; D2 with 3+ victims; D2 + family match; D9 kit approval amount; bait
  contract with 3+ victims; R-A1 with 3+ victims; D10 multi-victim + kit deadline; K7/K8 batch or kit-router drain;
  K5 hub with 3+ one-shot workers; K4 ms-deadline + pull; K9 owner-collector with 3+ victims). T2 strong (D2 with 1-2 victims;
  D4; D8 3+ victims; bait contract 1-2 victims; R-A1 2 victims; D10 multi-victim or kit deadline; family / kit
  signature / owner-gated puller with activity; K4 alone; K5 hub; K12 3+ funded workers; K9; K2 exact runtime; K6;
  K14 twin of a T1). T3 suspect (D3 alone; D6; D7 no-arg; D8 1-2 victims; R-A1 1 victim;
  D10 single; red-flag selectors; family / kit signature / puller without activity). The
  score is an additive documented weight (`constants.SCORE`); the tier is the published field. Tiers are leads for
  investigation, not findings of fact. Operator/affiliate roles and `deposit_sweep` links are inferences.
* Etherscan calls are best effort (free plans may not cover BSC/Base); failures never break a run.

MIT licensed.
