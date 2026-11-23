"""Constants: chains, topics, selectors, allowlist, score weights."""
import os
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
                explorer="https://etherscan.io", native="ETH", max_blocks=100, block_sec=12, source="receipts", chunk=20, wa="ethereum", cg="ethereum"),
    "bsc": dict(id=56, rpc_env="BSC_RPC_URL", rpc="https://bsc-rpc.publicnode.com",
                explorer="https://bscscan.com", native="BNB", max_blocks=800, block_sec=0.75, source="logs", chunk=100, wa="bsc", cg="binancecoin"),
    "base": dict(id=8453, rpc_env="BASE_RPC_URL", rpc="https://base-rpc.publicnode.com",
                 explorer="https://basescan.org", native="ETH", max_blocks=400, block_sec=2, source="receipts", chunk=60, wa="base", cg="ethereum"),
}
# default block source per chain (measured 2026-11-23, 20 blocks each, see README "Block source"): receipts on ETH/Base
# (enables D8 / R-A1 and removes capped tx lookups); BSC stays on getLogs (receipts + D8 lookups: ~16x wall time per
# block, 800 blocks/run would not fit the budget). Env DRAINERWATCH_SOURCE / --source override all chains.
INITIAL_BLOCKS = 300
CONFIRMATIONS = 2

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
                 "Multicall()", "NetworkMerge()", "ClaimAirdrop()"]
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
KIT_DEPOSIT_GAS = {100_000, 5_000_000, 900_000}      # default / Arbitrum+Avalanche / Pulse
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
    # canonical bridges
    "0x3154cf16ccdb4c6d922629664174b904d80f2c35": "Base L1StandardBridge",
    "0x99c9fc46f92e8a1c0dec1b1747d010903e884be1": "Optimism L1StandardBridge",
}
WRAPPED_NATIVE = {  # token -> native symbol (priced as that coin)
    "eth": {"0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2": "ETH"},
    "bsc": {"0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c": "BNB", "0x2170ed0880ac9a755fd29b2688956bd959f933f8": "ETH"},
    "base": {"0x4200000000000000000000000000000000000006": "ETH"},
}
STABLES = {  # priced 1.0 by ADDRESS (not by symbol: scam tokens copy symbols)
    "eth": {"0xdac17f958d2ee523a2206206994597c13d831ec7", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
            "0x6b175474e89094c44da98b954eedeac495271d0f", "0x4c9edd5852cd905f086c759e8383e09bff1e68b3",
            "0xc5f0f7b66764f6ec8c8dff7ba683102295e16409", "0x1abaea1f7c830bd89acc67ec4af516284b1bc33c"},
    "bsc": {"0x55d398326f99059ff775485246999027b3197955", "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d",
            "0xe9e7cea3dedca5984780bafc599bd69add087d56", "0xc5f0f7b66764f6ec8c8dff7ba683102295e16409"},
    "base": {"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca",
             "0x50c5725949a6f0c72e6c4a641f24049a917db0cb", "0xfde4c96c8593536e31f229ea8f37b2ada2699bb2"},
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

# score weights (additive, capped at 100)
SCORE = {"seed": 50, "approval_fingerprint": 50, "bait_payable": 35, "kit_signature": 25, "split_xtx": 35,
         "foreign_recipient_swap": 15, "foreign_swap_multi": 20, "foreign_swap_kit": 30, "owner_gated_puller": 10,
         "cluster_inherited": 0, "split_pull": 45, "victims3": 15, "family_match": 25, "pays_known_operator": 30,
         "multi_victim_pull": 20, "eoa_spender_pull": 15, "eoa_spender_multi": 20, "pays_inferred_operator": 10, "spoof_split": 5, "eip7702_sweeper": 15, "redflag_payable": 10, "redflag_selectors": 10,
         "activity": 5, "usd_1k": 5, "wa_scam": 10,
         # kit notes K1-K14 rules
         "kit_exact": 40, "kit_deposit": 30, "gen_back_transfer": 5, "ms_deadline": 40, "oneshot_hub": 35,
         "oneshot_multi": 20, "prefund_hub": 10, "prefund_multi": 15, "batch_approval_drain": 50,
         "kit_router_swap": 50, "owner_collect": 30, "eip7702_operator": 10, "cross_chain": 10}
