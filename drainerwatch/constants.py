"""Constants: chains, topics, selectors, allowlist, score weights."""
import os
import re
from pathlib import Path

from .util import selector, topic

ROOT = Path(os.environ.get("DRAINERWATCH_HOME") or Path(__file__).resolve().parent.parent)
DATA_DIR = ROOT / "data"
SITE_DIR = ROOT / "site"
DB_PATH = DATA_DIR / "drainerwatch.sqlite"
SEEDS_CSV = DATA_DIR / "seeds.csv"
ALLOWLIST_CSV = DATA_DIR / "allowlist.csv"   # optional operator additions: chain,address,note
TEMPLATE = Path(__file__).resolve().parent / "template.html"

CHAINS = {
    "eth": dict(id=1, rpc_env="ETH_RPC_URL", rpc="https://ethereum-rpc.publicnode.com",
                explorer="https://etherscan.io", native="ETH", max_blocks=100, block_sec=12, source="receipts", chunk=20, wa="ethereum", cg="ethereum", share=0.25),
    "bsc": dict(id=56, rpc_env="BSC_RPC_URL", rpc="https://bsc-rpc.publicnode.com",
                explorer="https://bscscan.com", native="BNB", max_blocks=2000, block_sec=0.45, source="logs", chunk=100, wa="bsc", cg="binancecoin", share=0.5),
    "base": dict(id=8453, rpc_env="BASE_RPC_URL", rpc="https://base-rpc.publicnode.com",
                 explorer="https://basescan.org", native="ETH", max_blocks=450, block_sec=2, source="receipts", chunk=60, wa="base", cg="ethereum", share=0.1),
    # TRON (TronGrid HTTP API, not JSON-RPC): own ingestion in tron_scan.py; ~3 s blocks -> ~200-300 blocks per 10-15 min
    "tron": dict(id=None, kind="tron", rpc_env="TRON_API_URL", rpc="https://api.trongrid.io (keys) / tron-rpc.publicnode.com",
                 explorer="https://tronscan.org/#", tx_path="transaction", native="TRX", max_blocks=300, max_blocks_keyless=60, block_sec=3,
                 source="blocks", chunk=20, wa="tron", cg="tron", share=0.15),
}
# share: fraction of the run's scan budget; slices are cumulative in run order, so time a chain leaves unused goes to the
# chains after it. Measured 2026-11-24 (warm cache): ETH 75 blocks ~70 s, Base 411 ~27 s, TRON 300 ~35 s, BSC (getLogs +
# D2/D3 tx lookups) ~0.44 s per block, i.e. about real time: BSC runs last, takes what is left and records gaps.
DEFAULT_CHAIN_ORDER = "eth,base,tron,bsc"
EVM_CHAINS = [c for c, cfg in CHAINS.items() if cfg.get("kind", "evm") == "evm"]
# default block source per chain (measured 2026-11-23, 20 blocks each, see README "Block source"): receipts on ETH/Base
# (enables D8 / R-A1 and removes capped tx lookups); BSC stays on getLogs (receipts + D8 lookups: ~16x wall time per
# block, 800 blocks/run would not fit the budget). Env DRAINERWATCH_SOURCE / --source override all chains.
INITIAL_BLOCKS = 300
CONFIRMATIONS = 2
MAX_GAPS = 50                  # head-first scanning: skipped block ranges kept per chain (meta gaps:<chain>)

SCAMSNIFFER_URL = "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json"
SEEDS_REFRESH_SEC = 6 * 3600
WA_RAW = "https://raw.githubusercontent.com/prettydeath/wallet-attribution/main/data/{name}.csv"
WA_LOCAL_DEFAULT = r"C:\Claude code\wallet-attribution\data"
LABELS_REFRESH_SEC = 24 * 3600
ETHERSCAN_V2 = "https://api.etherscan.io/v2/api"
COINGECKO = "https://api.coingecko.com/api/v3/simple/price"

TOPIC_TRANSFER = topic("Transfer(address,address,uint256)")
TOPIC_APPROVAL = topic("Approval(address,address,uint256)")
TOPIC_APPROVAL_ALL = topic("ApprovalForAll(address,address,bool)")
LOG_TOPICS = [TOPIC_TRANSFER, TOPIC_APPROVAL, TOPIC_APPROVAL_ALL]

SEL_SYMBOL = "0x" + selector("symbol()")
SEL_DECIMALS = "0x" + selector("decimals()")

ZERO = "0x" + "0" * 40

# Red-flag (drainer kit) function names; only capitalised kit names (plain claim() is far too common).
REDFLAG_NAMES = ["Claim()", "ClaimReward()", "ClaimRewards()", "SecurityUpdate()", "Connect()", "Execute()",
                 "Multicall()", "NetworkMerge()", "ClaimAirdrop()",
                 # W3: no-arg bait names caught by the payable fallback of fake-token drainers (Verify() 0x143087ee,
                 # Claim() 0x3158952e, public vendor reports 2025) and the "ClaimReward" template's Gift()
                 "Verify()", "Gift()"]
# MS Drainer "Beta" bait functions (MS Drainer kit notes S1): payable, the argument is the kit CUSTOMER's payout
# wallet (the contract is multi-tenant: balance[arg] += msg.value, the customer later calls withdraw).
BAIT_ADDR_NAMES = ["Claim(address)", "ClaimReward(address)", "ClaimRewards(address)", "SecurityUpdate(address)",
                   "Connect(address)", "Execute(address)", "Swap(address)", "Multicall(address)"]
BAIT_ADDR_SELECTORS = {selector(n): n for n in BAIT_ADDR_NAMES}
# companion set (fingerprint, beta + older deployment); kit family `ms_drainer` = >=1 bait + >=2 companions
MS_COMPANION_NAMES = ["getOwner()", "getBalance()", "getUserBalance(address)", "getWithdrawStatus(address)",
                      "setWithdrawStatus(bool)", "withdraw(address)", "withdraw(address,uint256)"]
MS_COMPANION_SELECTORS = {selector(n): n for n in MS_COMPANION_NAMES}
MS_WITHDRAW_SELECTORS = {selector("withdraw(address)"): "withdraw(address)",
                         selector("withdraw(address,uint256)"): "withdraw(address,uint256)"}
MS_MIN_BAIT, MS_MIN_COMPANION = 1, 2
# "VerifyAccount" TRON puller family (case notes case A, rule R-A3); kit family `verify_account` = >=2 of 3
VERIFY_ACCOUNT_NAMES = ["Verify20(address,address,address,uint256)", "Verify10(address,uint256)",
                        "withdrawAllTrxTo(address)"]
VERIFY_ACCOUNT_SELECTORS = {selector(n): n for n in VERIFY_ACCOUNT_NAMES}
VERIFY_ACCOUNT_MIN = 2
# "buytron" TRON kit (PhishDestroy gist 2026-02-09, public): fake TRX purchase, unlimited USDT approval to a small contract
# whose admin pulls with a stored token address. Exact dispatcher sets of its two published contracts.
BUYTRON_FAMILIES = {
    frozenset({selector("pullFunds(address,address,uint256)"), selector("admin()"), selector("token()")}): "buytron_swap_trx",
    frozenset({selector("transferFrom(address,address,uint256)"), selector("usdt()"), selector("owner()")}): "buytron_swap_proxy",
}
REDFLAG_SELECTORS = {selector(n): n for n in REDFLAG_NAMES}
REDFLAG_SELECTORS.update(BAIT_ADDR_SELECTORS)
REDFLAG_SELECTORS.update(VERIFY_ACCOUNT_SELECTORS)

# ---- kit notes K1-K14 (MS Drainer "PhishLab 20.11.2024" + instances, OwnerCollector) ----
# K1 MS_NEW public contract: every bait takes (address depositer, address handler, address keeper, uint8 percent,
# bool is_cashback), payable. handler = kit customer, keeper = worker (fee receiver), depositer = paying address.
MS_NEW_FUNCS = ["Airdrop", "Approve", "Cashback", "Claim", "ClaimReward", "ClaimRewards", "Connect", "Deposit",
                "Execute", "Multicall", "Permit", "Process", "Register", "Rewards", "SecurityUpdate", "Swap",
                "Transfer", "Verify", "Withdraw"]
MS_NEW_SELECTORS = {selector(f + "(address,address,address,uint8,bool)"): f + "(address,address,address,uint8,bool)"
                    for f in MS_NEW_FUNCS}
MS_NEW_COMPANION_NAMES = ["changePercentage(uint8)", "claimSalary()", "disableSalary()", "enableSalary()",
                          "salaryStatus()", "setReceiver(address)"]
MS_NEW_COMPANION_SELECTORS = {selector(n): n for n in MS_NEW_COMPANION_NAMES}
MS_NEW_MIN_BAIT, MS_NEW_MIN_COMPANION, MS_NEW_MAX_PERCENT = 3, 2, 99
SEL_MS_NEW_DEPOSIT = selector("Deposit(address,address,address,uint8,bool)")       # 0x38928522
REDFLAG_SELECTORS.update(MS_NEW_SELECTORS)
# K6: Wallet-Randomizer native leg: fresh EOA (nonce <= 2) calls Deposit with ~ its whole balance and a fixed gasLimit
KIT_DEPOSIT_GAS = {100_000, 150_000, 5_000_000, 900_000}   # default / secondary (N8) / Arbitrum+Avalanche / Pulse
KIT_DEPOSIT_MAX_NONCE, KIT_DEPOSIT_MIN_SHARE = 2, 0.90
# K2 Contract Generator bait: one no-arg payable selector, runtime 894 B, storage-held receivers (slot 1 main_receiver,
# slot 2 = fee_receiver | uint8 fee_percent << 160 | bool fee_state << 168), 2 x transfer() (2300 gas stipend 0x08fc)
GEN_BAIT_NAMES = ["Claim()", "ClaimReward()", "ClaimRewards()", "Connect()", "Deposit()", "Execute()", "Multicall()",
                  "Permit()", "Process()", "Register()", "Rewards()", "SecurityUpdate()", "Swap()", "Transfer()",
                  "Verify()", "Withdraw()"]
GEN_BAIT_SELECTORS = {selector(n): n for n in GEN_BAIT_NAMES}
GEN_BAIT_SIZE = (850, 950)
GEN_BAIT_SKELETON = "c7db65c17065432296d8058185fa9500ac71f842343c3516da1de8a11efdcc19"
# keccak256 of the exact runtime of the 16 generator variants, derived statically from the kit's init code (CODECOPY
# slice; receivers live in storage, so the runtime does not depend on the constructor arguments)
GEN_BAIT_RUNTIME_KECCAK = {
    "0x67db0cafc2534ae01177f8dbf0edf693989657eab26567337432843433d4d7df": "Claim()",
    "0x57991a544f6c896c1785e6e841331b18757e92efc082a8968b201ad8b03dd409": "ClaimReward()",
    "0x148fd3efd28a2f557b53f4d8696e46b6b56d84962dcdc4324d12aee38dd49190": "ClaimRewards()",
    "0x30204eac4bde5500daa0e659c5db939c8efc42e3a1f95278faa05dda2f2bad5b": "Connect()",
    "0xd6036569ebe192c18778d6976ad3f1403f40cfa48799604ecc0057fb9b1338f1": "Deposit()",
    "0xc0808496c4dccc0b923feb25b4996749417260dfee85e84b71f7d80e4c2516d1": "Execute()",
    "0x1927ea51433bcd753f7315ad7c1f1c2cb7d50de4d52e171aaafef5aaec2aac7e": "Multicall()",
    "0x109fb3c01630470bce82d898703a885db09bc3267445688fdc0071eb29368a61": "Permit()",
    "0x981e94c7b8491a3c5a974513ac0caa6542d96ce500a2e264ee639482d7a3014d": "Process()",
    "0x48fb2025363800c6419a2c372e0678c1b6549fb8f4f6c7f95a3bcc1aad93e6fa": "Register()",
    "0x68e76dd632861e0931f83c7dbad32cfae43af106b3f7c0f592ef49695c1771d5": "Rewards()",
    "0xfa56a0afc61a450fa80f5e8aa186d6ab46bfb781f17708437183749ca3810349": "SecurityUpdate()",
    "0xba352657cc6dacd75900f389c096d6e1b15aa8ae36da9c50c487fb2cd135663d": "Swap()",
    "0xe42dd0082b28566a23f84d2bf60bd606874ce9981818aa4ecaaed209b9ed3975": "Transfer()",
    "0x94354d8286413c5d55dd1fd9125a3c3d41392caaeb1e1e4e8b5f4a80a43a09fb": "Verify()",
    "0x5993af746b0dc4a10ad65092caeb343aa880e88ad59b1659d4701ea8de64c8dc": "Withdraw()",
}
GEN_FRESH_SEC = 3600            # bait created <= 1 h before the victim call: `fresh` marker
GEN_MAX_USES = 3                # the generator reuses one contract <= 3 times
GEN_BACK_WINDOW = 50            # blocks after the creation in which the deployer "back" transfer is looked for
# capture set of the ETH block pass for value > 0 calls (names for every selector)
BAIT_CAPTURE = dict(REDFLAG_SELECTORS)
BAIT_CAPTURE.update(GEN_BAIT_SELECTORS)
# ---- kit notes N1-N11 (MS Drainer public contracts "Trusty", 2023-2026) ----
# N2 `trusty_v1`: the kit's 2023 public pass-through contract (bait(address) forwards msg.value minus a 5-10 % owner fee)
TRUSTY_V1_NAMES = ["Fee(address)", "getFee()", "changePercentage(uint8)"]
TRUSTY_V1_SELECTORS = {selector(n): n for n in TRUSTY_V1_NAMES}        # 32b80676 / ced72f87 / d285660d
TRUSTY_V1_MIN_BAIT = 3
# N3 the kit's two PUBLIC shared contracts (Etherscan-verified ContractName "Trusty"); same address and runtime on
# Ethereum, BSC, Polygon, Arbitrum and Base. Every successful bait call to them is a kit victim.
KIT_PUBLIC_CONTRACTS = {
    "0x0007039b77d22042afc1a9c3b3da11837b730000": "trusty_v1",     # bait(address): sender = kit customer
    "0x0000366a6afea972e4353b070ad904744a530000": "ms_new",        # 5-arg bait: handler = customer, keeper = worker
}
# keccak256 of their exact runtime (identical on all five chains; no immutables)
KIT_PUBLIC_RUNTIME_KECCAK = {
    "0x470ec6767359f7d4c64f8fd23415c5ff5132dbd7cd244a1a46935237e84ee0b0": "trusty_v1",   # 2 936 B
    "0xd4f77d9e0803ce4a4ae809615b5896f2b86e792d8ee924b71c556015356a4e6e": "ms_new",      # 5 436 B
}
# N4 dust-value approvals: approve / increaseAllowance / increaseApproval sent with 1..8 wei (kit bug; usually reverts)
SEL_APPROVE = selector("approve(address,uint256)")                    # 095ea7b3
SEL_INCREASE_ALLOWANCE = selector("increaseAllowance(address,uint256)")  # 39509351
SEL_INCREASE_APPROVAL = selector("increaseApproval(address,uint256)")    # d73dd623
APPROVE_SELECTORS = {SEL_APPROVE: "approve", SEL_INCREASE_ALLOWANCE: "increaseAllowance",
                     SEL_INCREASE_APPROVAL: "increaseApproval"}
DUST_APPROVE_MAX_WEI = 8
# N5 emergency gas: a small native transfer to the victim followed within 30 min by the victim's approval to the funder
EMERGENCY_GAS_WINDOW_SEC = 30 * 60
EMERGENCY_GAS_MAX_USD = 50.0
EMERGENCY_GAS_KEEP = 160             # blocks of plain native transfers kept for the N5 lookup (ETH, 30 min + margin)
# N7 kit-amount allowance increase to a legitimate router, then a foreign-recipient swap by the same owner in another tx
KIT_ROUTER_XTX_SEC = 300
# N9 vanity kit addresses (0x000... prefix, ...0000 suffix): score booster only, never a tier on its own
KIT_VANITY_RE = re.compile(r"^0x000[0-9a-f]{33}0000$")

# K9 OwnerCollector (owner-gated puller, EVM analogue of R-A2): dispatcher must carry >= 5 of these 6, incl. a collect fn
OWNER_COLLECTOR_NAMES = ["collectToOwner(address,address,uint256)", "collectAllFrom(address,address)",
                         "permitAndCollect(address,address,uint256,uint256,uint8,bytes32,bytes32)",
                         "rescueToken(address,address,uint256)", "setOwner(address)", "owner()"]
OWNER_COLLECTOR_SELECTORS = {selector(n): n for n in OWNER_COLLECTOR_NAMES}
OWNER_COLLECTOR_MIN = 5
OWNER_COLLECTOR_T1_VICTIMS = 3
# K4 millisecond deadlines (Date.now() + 1000*60*60*24*356 used as a seconds field)
SEL_PERMIT_2612 = selector("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)")               # d505accf
SEL_PERMIT_DAI = selector("permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)")            # 8fcbaf0c
SEL_PERMIT2_SINGLE = selector("permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)")   # 2b67b570
SEL_PERMIT2_BATCH = selector("permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)")  # 2a2d80d1
PERMIT_SELECTORS = {SEL_PERMIT_2612: "permit(EIP-2612)", SEL_PERMIT_DAI: "permit(DAI)",
                    SEL_PERMIT2_SINGLE: "Permit2.permit(single)", SEL_PERMIT2_BATCH: "Permit2.permit(batch)"}
MS_DEADLINE_MIN, MS_DEADLINE_MAX = 10 ** 12, 10 ** 13
# K5 / K12 one-shot EOA spenders funded by a hub (Wallet Randomizer): pull with nonce <= 3, leftover back with gas 25 200
SEL_P2_TRANSFER_FROM = selector("transferFrom(address,address,uint160,address)")            # 36c78516
SEL_P2_TRANSFER_FROM_BATCH = selector("transferFrom((address,address,uint160,address)[])")  # 0d58b1db
ONESHOT_RETURN_GAS = 25_200          # 21 000 x 1.2 (ethers gas multiplier of the kit)
ONESHOT_RETURN_GASES = {ONESHOT_RETURN_GAS, 30_000}   # N8: older kit builds forward with a fixed gasLimit of 30 000
ONESHOT_MAX_NONCE = 3
ONESHOT_FUND_WINDOW = 30             # blocks between the hub's gas transfer and the worker's pull
ONESHOT_RETURN_WINDOW = 50           # blocks between the pull and the leftover return
ONESHOT_T1_WORKERS = 3
ONESHOT_KEEP = 60                    # blocks of plain native transfers kept in memory for the fund lookup
# K7 / K8 batch approvals (EIP-5792 wallet_sendCalls) and kit-amount approvals to legitimate routers
UINT256_MAX = 2 ** 256 - 1
BATCH_APPROVAL_MIN = 2
SEL_V3_EXACT_INPUT_SINGLE = selector("exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))")
SEL_R02_EXACT_INPUT_SINGLE = selector("exactInputSingle((address,address,uint24,address,uint256,uint256,uint160))")
V3_KIT_FEE, V3_KIT_DEADLINE, V3_KIT_TOLERANCE = 3000, 300, 60
D7_T1_VICTIMS = 3              # bait(address) contract with >= 3 distinct paying victims: T1, else T2

# D9 approval_fingerprint: Approval amounts hard-coded by a kit (not uint256 max). Each entry is a FINGERPRINT.
KIT_APPROVAL_AMOUNTS = {
    # MS Drainer: parseEther("1158472395435294898592384258348512586931256") (MS Drainer kit notes S3)
    0xb88e282822ab5ed106947c1c60af583c1741a38e858de00000: "ms_drainer",
}

# D10 foreign_recipient_swap (MS Drainer kit notes S4): victim-signed DEX swap paying an EOA that is not tx.from
SWAP_V2_NAMES = ["swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
                 "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
                 "swapExactTokensForETHSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)",
                 "swapExactTokensForTokensSupportingFeeOnTransferTokens(uint256,uint256,address[],address,uint256)"]
SWAP_V2_SELECTORS = {selector(n): n for n in SWAP_V2_NAMES}
# N6: ETH-in V2 swaps (swapExactETHForTokens[SupportingFeeOnTransferTokens]): amountIn = tx.value
SWAP_V2_ETH_IN_NAMES = ["swapExactETHForTokens(uint256,address[],address,uint256)",
                        "swapExactETHForTokensSupportingFeeOnTransferTokens(uint256,address[],address,uint256)"]
SWAP_V2_ETH_IN_SELECTORS = {selector(n): n for n in SWAP_V2_ETH_IN_NAMES}     # 7ff36ab5 / b6f9de95
SWAP_R02_SELECTORS = {selector("swapExactTokensForTokens(uint256,uint256,address[],address)"):
                      "swapExactTokensForTokens(uint256,uint256,address[],address)"}   # SwapRouter02 (no deadline)
SEL_MULTICALL_DEADLINE = selector("multicall(uint256,bytes[])")
D10_MIN_VICTIMS, D10_WINDOW = 3, 24 * 3600
D10_KIT_DEADLINE, D10_KIT_TOLERANCE = 99990, 900   # MS Drainer: deadline = now + 99 990 s

# R-A1 cross-tx split: same caller + victim + token, >= 2 pulls in different txs within 60 s to >= 2 recipients
XSPLIT_MAX_GAP = 60
XSPLIT_MIN_SHARE, XSPLIT_MAX_SHARE = 0.60, 0.99    # TRON VerifyAccount family splits 98/2 in two txs
SEL_TRANSFER_FROM = selector("transferFrom(address,address,uint256)")

# detector parameters
D2_MIN_SHARE, D2_MAX_SHARE = 0.60, 0.95   # 0.99 was measured 2026-11-23: +1 T2 FP on dev, +1 on live, 0 ETH recall gain
D3_MIN_VICTIMS, D3_WINDOW = 3, 24 * 3600
D4_MIN_TXS = 2
# D8 eoa_spender_pull (receipts source only): an EOA calls token.transferFrom / Permit2 for another EOA
PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"
D8_MIN_VICTIM_NONCE = 3       # custodial deposit addresses (approve once, swept by the hot wallet) have nonce 1-2
D8_MAX_SPENDER_NONCE = 2000   # high-volume sweepers / payment gateways; drainer operators in the dev set: <= ~1.1k
D8_MAX_LOOKUPS = 1500         # nonce lookups per chunk (codes: 3x); truncation is counted in stats d8_truncated
FAMILY_JACCARD = 0.8
FAMILY_MIN_SELECTORS = 3
FAMILY_MIN_CODE = 100          # bytes; minimal proxies (45 B) share one skeleton and must never form a family
MIN_USD = 1.0
APPROVAL_KEEP_SEC = 7 * 86400
SWEEP_WINDOW = 72 * 3600
SWEEPER_MAX_CODE = 1024

# Benign allowlist (tx.to must never become a drainer). Chain-agnostic: many are CREATE2 at the same address.
# Sources: official docs / deployment lists of each protocol; extend per operator in data/allowlist.csv.
ALLOWLIST = {
    # ERC-4337 EntryPoints (github.com/eth-infinitism/account-abstraction): bundlers relay user operations of
    # smart accounts and 7702-delegated EOAs, so tx.from != victim is normal there
    "0x5ff137d4b0fdcd49dca30c7cf57e578a026d2789": "ERC-4337 EntryPoint v0.6",
    "0x0000000071727de22e5e9d8baf0edac6f37da032": "ERC-4337 EntryPoint v0.7",
    "0x4337084d9e255ff0702461cf8895ce9e3b5ff108": "ERC-4337 EntryPoint v0.8",
    # Tangem wallet gasless EIP-7702 entry point (Etherscan verified ContractName Tangem7702GaslessEntryPoint):
    # relays delegated-EOA batches, so third-party pulls/splits are normal there
    "0xf67e35af6a18a01702e6c2f1e18a63c2fc3a528c": "Tangem 7702 Gasless EntryPoint",
    # MetaMask Delegation Framework DelegationManager (Etherscan verified ContractName DelegationManager on eth and base,
    # same address on every chain): redeems ERC-7710 delegations of smart accounts, so third-party pulls are normal there
    "0xdb9b1e94b5b69df7e401ddbede43491141047db3": "MetaMask DelegationManager",
    # CoW Protocol GPv2Settlement (docs.cow.fi)
    "0x9008d19f58aabd9ed0d60971565aa8510560ab41": "CoW GPv2Settlement",
    # UniswapX reactors (github.com/Uniswap/UniswapX deployments)
    "0x6000da47483062a0d734ba3dc7576ce6a0b645c4": "UniswapX ExclusiveDutchOrderReactor",
    "0x00000011f84b9aa48e5f8aa8b9897600006289be": "UniswapX V2DutchOrderReactor",
    "0x000000001ec5656dcdb24d90dfa42742738de729": "UniswapX PriorityOrderReactor",
    # 1inch routers (docs.1inch.io)
    "0x1111111254eeb25477b68fb85ed929f73a960582": "1inch AggregationRouter v5",
    "0x111111125421ca6dc452d289314280a0f8842a65": "1inch AggregationRouter v6",
    "0x1111111254fb6c44bac0bed2854e76f90643097d": "1inch AggregationRouter v4",
    # 0x (docs.0x.org): Exchange Proxy, AllowanceHolder, Settler deployer
    "0xdef1c0ded9bec7f1a1670819833240f027b25eff": "0x ExchangeProxy",
    "0x0000000000001ff3684f28c67538d4d072c22734": "0x AllowanceHolder",
    "0x70bf6634ee8cb27d04478f184b9b8bb13e5f4710": "0x Settler deployer",
    # Uniswap routers (docs.uniswap.org)
    "0x66a9893cc07d91d95644aedd05d03f95e1dba8af": "Uniswap Universal Router v4",
    "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "Uniswap Universal Router",
    "0xef1c6e67703c7bd7107eed8303fbe6ec2554bf6b": "Uniswap Universal Router (old)",
    "0x6ff5693b99212da76ad316178a184ab56d299b43": "Uniswap Universal Router Base",
    "0x2626664c2603336e57b271c5c0b26f421741e481": "Uniswap SwapRouter02 Base",
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap SwapRouter02",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap SwapRouter",
    "0x000000000022d473030f116ddee9f6b43ac78ba3": "Permit2",
    # PancakeSwap (BSC)
    "0x10ed43c718714eb63d5aa57b78b54704e256024e": "PancakeSwap Router v2",
    "0x13f4ea83d0bd40e75c8222255bc855a974568dd4": "PancakeSwap Router v3",
    "0x1a0a18ac4becddbd6389559687d1a73d8927e416": "PancakeSwap Universal Router",
    # Safe (docs.safe.global supported networks)
    "0xd9db270c1b5e3bd161e8c8503c55ceabee709552": "Safe singleton 1.3.0",
    "0x3e5c63644e683549055b9be8653de26e0b4cd36e": "Safe L2 singleton 1.3.0",
    "0x41675c099f32341bf84bfc5382af534df5c7461a": "Safe singleton 1.4.1",
    "0x29fcb43b46531bca003ddc8fcb67ffe91900c762": "Safe L2 singleton 1.4.1",
    "0xa238cbeb142c10ef7ad8442c6d1f9e89e07e7761": "Safe MultiSend 1.3.0",
    "0x40a2accbd92bca938b02010e17a5b8929b49130d": "Safe MultiSendCallOnly 1.3.0",
    "0x9641d764fc13c8b624c04430c7356c1c7c8102e2": "Safe MultiSendCallOnly 1.4.1",
    "0x38869bf66a61cf6bdb996a6ae40d5853fd43b526": "Safe MultiSend 1.4.1",
    # ParaSwap / MetaMask swaps / Odos / KyberSwap
    "0x6a000f20005980200259b80c5102003040001068": "ParaSwap Augustus v6",
    "0xdef171fe48cf0115b1d80b88dc8eab59176fee57": "ParaSwap Augustus v5",
    "0x881d40237659c251811cec9c364ef91dc08d300c": "MetaMask Swap Router",
    "0xcf5540fffcdc3d510b18bfca6d2b9987b0772559": "Odos Router v2",
    "0x19ceead7105607cd444f5ad10dd51356436095a1": "Odos Router v2 Base",
    "0x6131b5fae19ea4f9d964eac0408e4408b66337b5": "KyberSwap MetaAggregationRouterV2",
    # Seaport / Blur
    "0x0000000000000068f116a894984e2db1123eb395": "Seaport 1.6",
    "0x00000000000000adc04c56bf30ac9d3c0aaf14dc": "Seaport 1.5",
    "0x000000000000ad05ccc4f10045630fb830b95127": "Blur Marketplace",
    "0x00000000006c3852cbef3e08e8df289169ede581": "Seaport 1.1",
    "0x00000000000001ad428e4906ae43d8f9852d0dd6": "Seaport 1.4",
    "0x00000000f9490004c11cef243f5400493c00ad63": "Seaport ConduitController",
    "0x1e0049783f008a0085193e00003d00cd54003c71": "OpenSea Seaport conduit",
    "0x004c00500000ad104d7dbd00e3ae0a5c00560c00": "OpenSea Seaport PausableZone",
    "0xca11bde05977b3631167028862be2a173976ca11": "Multicall3 (github.com/mds1/multicall)",
    # CoW Protocol flash-loan router (Etherscan verified ContractName FlashLoanRouter): deploys a per-order adapter that
    # uses the user's permit in the same tx (collateral swaps), the deploy-and-drain shape of W1b
    "0x9da8b48441583a2b93e2ef8213aad0ec0b392c69": "CoW FlashLoanRouter",
    # canonical bridges
    "0x3154cf16ccdb4c6d922629664174b904d80f2c35": "Base L1StandardBridge",
    "0x99c9fc46f92e8a1c0dec1b1747d010903e884be1": "Optimism L1StandardBridge",
}
WRAPPED_NATIVE = {  # token -> native symbol (priced as that coin)
    "eth": {"0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "ETH"},
    "bsc": {"0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c": "BNB", "0x2170ed0880ac9a755fd29b2688956bd959f933f8": "ETH"},
    "base": {"0x4200000000000000000000000000000000000006": "ETH"},
    # WTRX; the TRON zero address stands for native TRX in drains rows
    "tron": {"TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR": "TRX", "T9yD14Nj9j7xAB4dbGeiX9h8unkKHxuWwb": "TRX"},
}
STABLES = {  # priced 1.0 by ADDRESS (not by symbol: scam tokens copy symbols)
    "eth": {"0xdac17f958d2ee523a2206206994597c13d831ec7", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "0x6b175474e89094c44da98b954eedeac495271d0f", "0x4c9edd5852cd905f086c759e8383e09bff1e68b3",
            "0xc5f0f7b66764f6ec8c8dff7ba683102295e16409", "0x1abaea1f7c830bd89acc67ec4af516284b1bc33c"},
    "bsc": {"0x55d398326f99059ff775485246999027b3197955", "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
            "0xe9e7cea3dedca5984780bafc599bd69add087d56", "0xc5f0f7b66764f6ec8c8dff7ba683102295e16409"},
    "base": {"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca",
             "0x50c5725949a6f0c72e6c4a641f24049a917db0cb", "0xfde4c96c8593536e31f229ea8f37b2ada2699bb2"},
    # USDT-TRC20, USDC-TRC20 (issuer contracts; tronscan token pages)
    "tron": {"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8"},
}

# Labels from wallet-attribution
VASP_CATEGORIES = {"exchange", "instant-exchange", "service", "bridge", "mixer", "sanctioned", "gambling", "payment"}
# Category values present in the wallet-attribution csvs: entity, exchange, defi, scam, mev, frozen, gambling, bridge,
# hack, mining, sanctioned, mixer, service, extremism. Any label OUTSIDE this malicious set marks a legitimate
# subject: it is never flagged by any detector and never accepted as a payout wallet.
MALICIOUS_CATEGORIES = {"scam", "hack", "frozen", "sanctioned", "extremism"}

# Known AMM factories / pool deployers (a pool or pair they created is never a drainer). Addresses from the
# protocols' official deployment docs (Uniswap, SushiSwap, PancakeSwap, Aerodrome); extend as needed.
AMM_FACTORIES = {
    "0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f": "Uniswap V2 Factory (eth)",
    "0x8909dc15e40173ff4699343b6eb8132c65e18ec6": "Uniswap V2 Factory (base)",
    "0x1f98431c8ad98523631ae4a59f267346ea31f984": "Uniswap V3 Factory (eth)",
    "0x33128a8fc17869897dce68ed026d694621f6fdfd": "Uniswap V3 Factory (base)",
    "0xdb1d10011ad0ff90774d0c6bb92e5c5c8b4461f7": "Uniswap V3 Factory (bsc)",
    "0x000000000004444c5dc75cb358380d2e3de08a90": "Uniswap V4 PoolManager (eth)",
    "0xc0aee478e3658e2610c5f7a4a2e1777ce9e4f2ac": "SushiSwap V2 Factory (eth)",
    "0xbaceb8ec6b9355dfc0269c18bac9d6e2bdc29c4f": "SushiSwap V3 Factory (eth)",
    "0xca143ce32fe78f1f7019d7d551a6402fc5350c73": "PancakeSwap V2 Factory (bsc)",
    "0x0bfbcf9fa4f9c56b0f40a671ad40e0805a091865": "PancakeSwap V3 Factory",
    "0x41ff9aa7e16b8b1a8a8dc4f0efacd93d02d071c9": "PancakeSwap V3 PoolDeployer",
    "0x420dd381b31aef6683db6b902084cb0ffece40da": "Aerodrome V2 Factory (base)",
    "0x5e7bb104d84c7cb9b682aac2f3d509f5f406809a": "Aerodrome Slipstream Factory (base)",
}
POOL_SELECTORS = {"0dfe1681", "d21220a7"}      # token0(), token1(): AMM pair/pool dispatcher

# ---- TRON rules T-1..T-8 (case notes case A, kit notes K10/K11, web research 2026-11-23 sec. 2) ----
TRON_USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
TRON_SUN = 1_000_000
TRON_KIT_AMOUNTS = {10 ** 46: "tron_1e46"}          # K10: approve(spender, toSun("1e40")) = 10^46 units
TRON_KIT_FEE_LIMIT = 35 * TRON_SUN                  # ... sent with feeLimit 35 TRX
TRON_AML_FEE_LIMIT = 300 * TRON_SUN                 # K10 AML kit: approve(exact balance) with feeLimit 300 TRX
TRON_APPROVE_ALL_SELECTOR = "daea85c5"              # K10 kasumi "ApproveAll": daea85c5(address) on the token
TRON_CLAIMER_KEEP_SUN = 50 * TRON_SUN               # K11 Claimer: callValue = min(bal - 50 TRX, 0.8 * bal)
TRON_CLAIMER_SHARE, TRON_CLAIMER_TOL = 0.8, 0.02
TRON_PREFUND_MIN, TRON_PREFUND_MAX = 5 * TRON_SUN, 100 * TRON_SUN   # R-A5: whole-TRX gas pre-funding (case A: 20 TRX)
TRON_PREFUND_WINDOW = 6 * 3600                      # funding -> approval of the funder's spender
TRON_PREFUND_KEEP = 6 * 3600
TRON_PREFUND_T2 = 3                                 # >= 3 funded approvers with the same amount: T2
TRON_PREFUND_MIN_GAP = 3                            # funding and approval in the same block: sponsored-tx relayer
TRON_HUB_MAX_FUNDED = 30                            # a funder of > 30 wallets in 6 h is a distribution service
TRON_PERM_MIN_AGE_SEC = 30 * 86400                  # T-6: change >= 30 days after the account's first activity
TRON_PERM_T2 = 3                                    # accounts under one controller key: T2 (T1 needs a signed drain)
TRON_FEE_MIN_SUN = 5 * TRON_SUN                     # T-7 fixed TRX fee after a pull (TRXDrop: 30 TRX)
TRON_FEE_MAX_SUN = 100 * TRON_SUN                   # larger whole-TRX transfers after a pull are payments, not fees
TRON_FEE_WINDOW = 60
TRON_FEE_MIN_HITS = 2
TRON_POISON_MIN = 3                                 # T-8: zero-value transferFrom legs per subject per chunk
TRON_MAX_CONTRACT_LOOKUPS = 250                     # getcontractinfo per run (cached in tron_contracts)
TRON_MAX_ACCOUNT_LOOKUPS = 120                      # getaccount per run
# TRON benign allowlist (base58). Sources in comments; operator additions: data/allowlist.csv with chain=tron.
TRON_ALLOWLIST = {
    "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t": "USDT-TRC20 token contract",
}

# ---- web-research rules W1-W13 (public vendor reports and papers on drainer kits, 2023-2026) ----
# extra receipt log topics kept by the receipts source (getLogs chains do not fetch them)
TOPIC_LOG_SET_OWNER = topic("LogSetOwner(address)")                          # DSProxy setOwner
TOPIC_OWNERSHIP_TRANSFERRED = topic("OwnershipTransferred(address,address)")
TOPIC_SAFE_ADDED_OWNER = topic("AddedOwner(address)")                        # Safe 1.3 (data) / 1.4 (indexed)
TOPIC_SAFE_REMOVED_OWNER = topic("RemovedOwner(address)")
TOPIC_SAFE_CHANGED_THRESHOLD = topic("ChangedThreshold(uint256)")
TOPIC_SEAPORT_FULFILLED = topic("OrderFulfilled(bytes32,address,address,address,(uint8,address,uint256,uint256)[],"
                                "(uint8,address,uint256,uint256,address)[])")
TOPIC_P2_PERMIT = topic("Permit(address,address,address,uint160,uint48,uint48)")   # Permit2 AllowanceTransfer
TOPIC_P2_APPROVAL = topic("Approval(address,address,address,uint160,uint48)")
TOPIC_AUTH_USED = topic("AuthorizationUsed(address,bytes32)")                # EIP-3009 transferWithAuthorization
EXTRA_TOPICS = [TOPIC_LOG_SET_OWNER, TOPIC_OWNERSHIP_TRANSFERRED, TOPIC_SAFE_ADDED_OWNER, TOPIC_SAFE_REMOVED_OWNER,
                TOPIC_SAFE_CHANGED_THRESHOLD, TOPIC_SEAPORT_FULFILLED, TOPIC_P2_PERMIT, TOPIC_P2_APPROVAL, TOPIC_AUTH_USED]
# W2 vanity drainer addresses: >= 4 leading AND >= 4 trailing zero nibbles (fake-token / receiver contracts of several
# DaaS families). A prior only: it needs approvals from several EOAs, a bait payable call or a pull to become a label.
VANITY_RE = re.compile(r"^0x0000[0-9a-f]{32}0000$")
VANITY_MIN_APPROVERS = 3
# legitimate vanity-style infrastructure (Etherscan-verified ContractName in brackets); none of the known ones has the
# full 4+4 shape today, the list guards the rule against future deployments. Also in ALLOWLIST. Extend in allowlist.csv.
LEGIT_VANITY = {
    "0x00000000f9490004c11cef243f5400493c00ad63": "Seaport ConduitController (ConduitController)",
    "0x1e0049783f008a0085193e00003d00cd54003c71": "OpenSea Seaport conduit (Conduit)",
    "0x004c00500000ad104d7dbd00e3ae0a5c00560c00": "OpenSea Seaport zone (PausableZone)",
    "0xca11bde05977b3631167028862be2a173976ca11": "Multicall3 (Multicall3)",
    "0x00000000006c3852cbef3e08e8df289169ede581": "Seaport 1.1 (Seaport)",
    "0x00000000000001ad428e4906ae43d8f9852d0dd6": "Seaport 1.4 (Seaport)",
    "0x000000000022d473030f116ddee9f6b43ac78ba3": "Permit2",
    "0x0000000071727de22e5e9d8baf0edac6f37da032": "ERC-4337 EntryPoint v0.7",
}
# legitimate EIP-7702 delegate implementations (wallet vendors' published deployments): batches through them are
# normal; W8b looks at WHAT the batch does, W8a never flags them
LEGIT_7702_DELEGATES = {
    "0x63c0c19a282a1b52b07dd5a65b58948a07dae32b": "MetaMask EIP7702StatelessDeleGator",
    "0xd2e28229f6f2c235e57de2ebc727025a1d0530fb": "Trust Wallet 7702 delegate",
    "0x5a7fc11397e9a8ad41bf10bf13f22b0a63f96f6d": "Ambire 7702 account",
}
# W1 deploy-and-drain: Etherscan getcontractcreation lookups per run for in-tx permit spenders (archive getCode first)
DEPLOY_DRAIN_MAX_LOOKUPS = 20
# W3 bait forward: share of msg.value that left the contract to a third address in the same tx (Etherscan internal
# transfers of the tx, else the contract balance delta over the block when the node still has that state)
BAIT_FORWARD_MIN = 0.95
BAIT_FORWARD_MAX_LOOKUPS = 30
# W4 token-like spender: ERC-20 dispatcher selectors (transfer, transferFrom, approve, balanceOf, totalSupply, allowance)
ERC20_SELECTORS = {"a9059cbb", "23b872dd", "095ea7b3", "70a08231", "18160ddd", "dd62ed3e"}
ERC20_MIN_SELECTORS = 4
# W5 owner takeover: owner-change event, then an outflow from the same contract sent by the new owner within N blocks
TAKEOVER_WINDOW_SEC = 3600
TAKEOVER_MAX_NEW_OWNER_NONCE = 50
# W7 NFT: setApprovalForAll to an EOA, then NFT transfers of the owner sent by that EOA within N seconds
NFT_OPERATOR_WINDOW_SEC = 3600
# W8a EIP-7702 batch authorizations: more than 5 authorities per tx to one delegate = mass use of leaked keys
AUTH_BATCH_MIN = 6
# W10 zero-value transferFrom poisoning on real stablecoins: lookalike = same first 3 and last 4 hex chars of an
# address the victim really transacted with in the last 20 minutes (CMU address-poisoning study, 2025)
POISON_MIN_LEGS = 3
POISON_PREFIX, POISON_SUFFIX = 3, 4
POISON_WINDOW_SEC = 20 * 60
# W11 documented DaaS split shares (affiliate share): 70/30, 80/20, 85/15, 90/10; +-0.5 percentage points
SHARE_GRID = (0.70, 0.80, 0.85, 0.90)
SHARE_GRID_TOL = 0.005
# W12 operator wallet: an EOA paid by >= K distinct flagged drainers (own T1/T2 evidence)
OPERATOR_WALLET_T2 = 3
# W13 serial deployer: >= K flagged one-shot contracts from one deployer / factory
SERIAL_DEPLOYER_T2 = 3

# score weights (additive, capped at 100)
SCORE = {"seed": 50, "approval_fingerprint": 50, "bait_payable": 35, "kit_signature": 25, "split_xtx": 35,
         "foreign_recipient_swap": 15, "foreign_swap_multi": 20, "foreign_swap_kit": 30, "owner_gated_puller": 10,
         "cluster_inherited": 0, "split_pull": 45, "victims3": 15, "family_match": 25, "pays_known_operator": 30,
         "multi_victim_pull": 20, "eoa_spender_pull": 15, "eoa_spender_multi": 20, "pays_inferred_operator": 10, "spoof_split": 5, "eip7702_sweeper": 15, "redflag_payable": 10, "redflag_selectors": 10,
         "activity": 5, "usd_1k": 5, "wa_scam": 10,
         # kit notes K1-K14 rules
         "kit_exact": 40, "kit_deposit": 30, "gen_back_transfer": 5, "ms_deadline": 40, "oneshot_hub": 35,
         "oneshot_multi": 20, "prefund_hub": 10, "prefund_multi": 15, "batch_approval_drain": 50,
         "kit_router_swap": 50, "owner_collect": 30, "eip7702_operator": 10, "cross_chain": 10,
         # kit notes N1-N11 rules
         "kit_confirmed": 50, "ms_cashback": 15, "dust_approve": 25, "dust_approve_kit": 50, "emergency_gas": 25,
         "emergency_gas_kit": 50, "emergency_gas_self": 10, "kit_vanity": 5,
         # TRON rules T-1..T-8
         "kit_pull": 40, "approval_kit_shape": 30, "aml_approve_transfer": 35, "approve_all_call": 30,
         "increase_max": 5, "prefund_approve": 15, "prefund_approve_multi": 25, "claimer_split": 40,
         "perm_hijack": 20, "perm_hijack_multi": 35, "perm_hijack_drain": 50, "fixed_fee": 20, "fixed_fee_multi": 30,
         "poison_zero": 5,
         # web-research rules W1-W13
         "vanity_drainer": 25, "deploy_drain": 40, "deploy_drain_weak": 15, "ghost_forward": 35, "ghost_forward_multi": 15, "bait_forward": 30,
         "bait_forward_multi": 10, "token_spender_pull": 20, "token_spender_multi": 15, "owner_takeover": 40,
         "owner_takeover_multi": 15, "safe_spender": 15, "safe_spender_pull": 20, "seaport_zero": 20, "seaport_zero_multi": 15,
         "nft_operator_pull": 35, "batch7702_approve": 40, "eip7702_batch": 10, "eip7702_chain0": 10, "share_grid": 10,
         "kept_share": 10, "operator_wallet": 30, "operator_wallet_multi": 15, "serial_deployer": 20, "serial_deployer_multi": 15}

# ---- GitHub / paper research rules G1-G13 (public detection bots, papers and vendor reports, 2023-2026) ----
# G1 fake-function native call: a no-argument call (input = selector only) with value > 0 to an address WITHOUT code
# (the money simply lands in the EOA; the wallet shows a "SecurityUpdate"/"Claim" method name to the victim)
FAKE_CALL_NAMES = ["SecurityUpdate()", "Claim()", "ClaimRewards()", "claimRewards()", "Connect()", "Execute()",
                   "Multicall()", "NetworkMerge()", "Verify()"]
FAKE_CALL_SELECTORS = {selector(n): n for n in FAKE_CALL_NAMES}
FAKE_CALL_MAX_RECIPIENT_NONCE = 2000     # busier receivers are services (public detection-bot filter)
FAKE_CALL_MAX_SENDER_NONCE = 9999
FAKE_CALL_NEAR_BLOCKS = 2                # the sender sent another tx within 2 blocks: scripted / normal use, skip
FAKE_CALL_T2_VICTIMS = 3
# G1 contract variant: value > 0 no-argument call to code, zero logs, >= 95 % of the value forwarded (W3 machinery)
FAKE_CALL_CONTRACT_MAX = 15
# G2 many funders: >= 7 distinct EOAs pay one fresh EOA similar native amounts (80-120 % of the median) within 5 days,
# not one same-nonce sybil batch (no nonce shared by more than a third of the funders)
FUNDERS_MIN = 7
FUNDERS_BAND = (0.8, 1.2)
FUNDERS_WINDOW_SEC = 5 * 86400
FUNDERS_MAX_RECIPIENT_NONCE = 50
FUNDERS_TRACK_MIN = 3                    # recipients with >= 3 distinct funders in one chunk are tracked across runs
# G3 deploy-time phishing contract (public NIP-8 / NIP-9 rules): no balanceOf, <= 1 event, <= 10 functions, a multicall
SEL_BALANCE_OF = selector("balanceOf(address)")
PHISH_MULTICALL_SELECTORS = {selector("multicall((address,bytes)[])"): "multicall((address,bytes)[])",
                             selector("multicall(address[],bytes[])"): "multicall(address[],bytes[])"}
PHISH_WITHDRAW_SELECTORS = {selector("withdraw()"), selector("withdraw(uint256,address)")}
PHISH_MAX_FUNCS, PHISH_MAX_EVENTS = 10, 1
PHISH_PULL_SELECTORS = {selector("transferFrom(address,address,uint256)"), selector("transfer(address,uint256)"),
                        selector("permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)"),
                        selector("transferFrom((address,address,uint160,address)[])")}
# G4 trusted-router pull + sweep: tokens of tx.from go in and leave the router to a third party with no swap
ROUTER_MULTICALL_SELECTORS = {selector("multicall(uint256,bytes[])"), selector("multicall(bytes32,bytes[])"),
                              selector("multicall(bytes[])")}
SEL_ROUTER_PULL = selector("pull(address,uint256)")                         # f2d5d56b
SEL_SWEEP_TOKEN = selector("sweepToken(address,uint256,address)")           # df2ab5bb
SEL_UNWRAP_WETH9 = selector("unwrapWETH9(uint256,address)")                 # 49404b7c
TRUSTED_ROUTERS = {
    "0x68b3465833fb72a70ecdf485e0e4c7bd8665fc45": "Uniswap SwapRouter02",
    "0x2626664c2603336e57b271c5c0b26f421741e481": "Uniswap SwapRouter02 Base",
    "0xe592427a0aece92de3edee1f18e0157c05861564": "Uniswap SwapRouter",
    "0x13f4ea83d0bd40e75c8222255bc855a974568dd4": "PancakeSwap Router v3",
    "0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad": "Uniswap Universal Router",
    "0x66a9893cc07d91d95644aedd05d03f95e1dba8af": "Uniswap Universal Router v4",
    "0x6ff5693b99212da76ad316178a184ab56d299b43": "Uniswap Universal Router Base",
    "0x1a0a18ac4becddbd6389559687d1a73d8927e416": "PancakeSwap Universal Router",
}
ROUTER_SWEEP_MIN_SHARE = 0.95
ROUTER_SWEEP_T2_VICTIMS = 2
# G5 NFT: Seaport TransferHelper bulkTransfer to one recipient. Selector checked against the Etherscan-verified ABI of
# TransferHelper: bulkTransfer(((uint8,address,uint256,uint256)[],address,bool)[],bytes32) = 0x32389b71
NFT_TRANSFER_HELPERS = {"0x0000000000c2d145a2526bd8c716263bfebe1a72": "Seaport TransferHelper"}
SEL_BULK_TRANSFER = "32389b71"
NFT_BULK_MIN_ITEMS = 2
NFT_BULK_T2_VICTIMS = 3
SEAPORT_FEE_MAX_OFFERER_SHARE = 0.01     # the offerer keeps <= 1 % of the payment (fees = ~100 %)
SEAPORT_NEAR_ZERO_WEI = 10 ** 15         # ... and the whole price is <= 0.001 native / wrapped native
# G6 address-poisoning extensions (CMU USENIX'25 parameters): tiny real-stablecoin transfers, counterfeit tokens,
# batched poison txs; poisoning stays T3 with no drains
POISON_TINY_MAX_USD = 10.0
POISON_TYPO_CHARS = 20                   # >= 20 matching leading+trailing hex chars: a typo, not poisoning
POISON_BATCH_MIN_LEGS = 6
POISON_MIN_ATTACK_RATIO = 0.5
# G7 lookalike contract creation: first 3 and last 3 hex characters of a busy contract
LOOKALIKE_CONTRACT_PRE, LOOKALIKE_CONTRACT_SUF = 3, 3
LOOKALIKE_BUSY_MIN = 20                  # a contract is "busy" with >= 20 txs / transfers in the chunk
# G8 counterfactual destination: tokens leave an address created in the same tx by a non-allowlisted factory
COUNTERFACTUAL_MAX_LOOKUPS = 40
CODEHASH_CLUSTER_MIN = 3
# G11 EIP-7702 forwarder delegate (initialize(address) + destination(), forwards native to slot 0)
FORWARDER_7702_SELECTORS = {selector("initialize(address)"), selector("destination()")}
SEL_7821_EXECUTE = selector("execute(bytes32,bytes)")                       # e9ae5c53
BATCH_DECOY_T2_VICTIMS = 2
# G12 PTXPhish ice-phishing prerequisite: a third party moves the victim's FULL token balance
FULL_BALANCE_MAX_LOOKUPS = 60
# G13 zero-nonce spender at approval time (EOA spender that never sent a tx)
ZERO_NONCE_MAX_LOOKUPS = 150
ZERO_NONCE_T2_VICTIMS = 3
# legitimate EIP-7702 delegate implementations, ContractName verified on Etherscan 2026-11-24 (eth / base)
LEGIT_7702_DELEGATES.update({
    "0x7702cb554e6bfb442cb743a7df23154544a7176c": "Coinbase EIP7702Proxy",
    "0x000100abaad02f1cfc8bbe32bd5a564817339e72": "Coinbase CoinbaseSmartWallet",
    "0x000000009b1d0af20d8c6d0a44e162d11f9b8f00": "Uniswap CaliburEntry",
    "0x4cd241e8d1510e30b2076397afc7508ae59c66c9": "eth-infinitism Simple7702Account",
    "0x000000004f43c49e93c970e84001853a70923b03": "Biconomy Nexus",
})
# protocols from public false-positive lists (ContractName verified on Etherscan 2026-11-24)
ALLOWLIST.update({
    "0x888888888889758f76e7103c6cbf23abbf58f946": "Pendle RouterV4",
    "0xa0c68c638235ee32657e8f720a23cec1bfc77c77": "Polygon RootChainManager",
    "0x40ec5b33f54e0e8a33a975908c5ba1c14e5bbbdf": "Polygon ERC20PredicateProxy",
    "0x0d05a7d3448512b78fa8a9e46c4872c88c4a0d05": "Odos Router v3",
    "0x0000000000c2d145a2526bd8c716263bfebe1a72": "Seaport TransferHelper",
})
# G10 TRON ABI / dispatcher markers of sweeper kits
TRON_SWEEPER_SELECTORS = {selector("trc20Withdraw(address,address,address[],uint256[])"): "trc20Withdraw",
                          selector("registerProxy()"): "registerProxy"}
TRON_SWEEP_ABI_MARKER = "sweep("
# optional private / operator lists (never committed): public false-positive lists, failsafe rescue wallets, intel labels
FP_LIST_DIR_ENV = "DRAINERWATCH_FP_DIR"
INTEL_CSV = DATA_DIR / "intel.csv"
SCORE.update({"fake_call": 20, "fake_call_multi": 15, "fake_call_contract": 25, "fake_call_contract_multi": 10,
              "many_funders": 15, "phish_deploy": 20, "phish_multicall": 35, "router_sweep": 30, "router_sweep_multi": 15,
              "nft_bulk": 10, "nft_bulk_multi": 25, "seaport_fee_drain": 20, "seaport_fee_multi": 15,
              "poison_tiny": 5, "poison_counterfeit": 5, "poison_batch": 5, "lookalike_contract": 10,
              "counterfactual_forward": 30, "counterfactual_multi": 15, "codehash_cluster": 5,
              "forwarder_7702": 25, "batch7702_decoy": 30, "batch7702_decoy_multi": 15, "full_balance_pull": 10,
              "increase_allowance_eoa": 15, "zero_nonce_spender": 15, "zero_nonce_multi": 15, "tron_sweeper_kit": 20,
              "cex_sweep_capped": 0})

# ---- TRON generic pulls (EVM D8 / D3 analogues) ----
TRON_PULL_MULTI = 3                  # distinct victims within 24 h: T2 (EOA signer) / T3 (contract)
TRON_SIGNER_MAX_TXS = 150            # a signer with more contract calls than this in one run is a service (sweeper / gateway)
TRON_SIGNER_MAX_VICTIMS_RUN = 40     # ... or pulling from more wallets than this in one run
TRON_SAME_OWNER_FUNDINGS = 2         # the signer funded the victim this many times: the signer's own deposit wallet
TRON_MAX_APPROVAL_MIN = 2 ** 128     # approve / increaseApproval amounts treated as "MAX"
TRON_GENERIC_MAX_LOOKUPS = 80        # contract-info lookups per run for the generic pull rules
TRON_GENERIC_RESERVE = 100           # ... never touching the last 100 of the run's contract lookups (kit rules)
SCORE.update({"tron_eoa_pull": 15, "tron_eoa_pull_multi": 25, "tron_contract_pull": 10, "tron_contract_pull_multi": 15,
              "tron_max_approval": 10})
