// Build-time: take the label vocabulary from drainerwatch/template.html (the single source the Python side keeps up
// to date) and write src/generated/vocab.json. Labels the template does not name yet get the EXTRA entries below;
// anything still unknown is shown with a humanised key at runtime.
import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const tplPath = resolve(here, '../../drainerwatch/template.html')
const out = resolve(here, '../src/generated/vocab.json')
const NAMES = ['TIERS', 'LABELS', 'FAMILIES', 'ROLES', 'VIA', 'KIND', 'SUBJ', 'NATIVE']

// web-research rules W1-W13 (drainerwatch/rollup.py, wrules.py) and evidence types not named in template.html yet
const EXTRA = {
  LABELS: {
    deploy_drain: ['Deploy and drain in one tx', 'The contract was created in the same transaction that moved a victim\'s tokens.'],
    ghost_forward: ['Ghost forwarder', 'Tokens left an address with no code and no transactions of its own: code that existed only inside the transaction.'],
    ghost_forward_multi: ['Ghost forwarder, 2+ addresses', 'Such a one-transaction contract moved tokens of two or more addresses.'],
    bait_forward: ['Payable bait that forwards', 'A victim paid a function and most of the value left to third addresses in the same transaction.'],
    bait_forward_multi: ['Forwarding bait, 2+ victims', 'Two or more victims paid it and the value was forwarded on.'],
    kept_share: ['Kept a share', 'The contract kept a share of the forwarded value, like a fee.'],
    token_spender_pull: ['Token-shaped spender', 'An ERC-20-like contract with DELEGATECALL pulled tokens from the wallets that approved it.'],
    token_spender_multi: ['Token-shaped spender, 2+ victims', 'It pulled tokens from two or more approving wallets.'],
    owner_takeover: ['Owner takeover', 'Became the owner of a contract and then moved tokens out of it.'],
    owner_takeover_multi: ['Owner takeover, 2+ contracts', 'Took over and emptied two or more contracts.'],
    safe_spender: ['Safe proxy spender', 'A Safe proxy that three or more wallets approved as a spender.'],
    safe_spender_pull: ['Safe proxy pulled tokens', 'That Safe proxy also pulled tokens from wallets that approved it.'],
    safe_approval: ['Approval to a Safe proxy', 'A wallet approved this Safe proxy as a spender.'],
    safe_pull: ['Pull by a Safe proxy', 'This Safe proxy pulled a wallet\'s approved tokens.'],
    seaport_zero: ['Zero-price NFT listing', 'Filled a Seaport order where the victim gave NFTs and received nothing.'],
    seaport_zero_multi: ['Zero-price listings, 2+ victims', 'Filled such orders for two or more victims.'],
    nft_operator_pull: ['NFT operator pull', 'A wallet set this address as operator for all its NFTs, and it then moved them.'],
    batch7702_approve: ['7702 batch approval', 'A victim\'s EIP-7702 account sent itself a batch that approved this wallet and moved tokens out.'],
    eip7702_batch: ['Mass 7702 delegation', 'Many EIP-7702 authorizations to this delegate in one transaction.'],
    eip7702_chain0: ['7702 delegation on every chain', 'Authorizations signed with chainId 0, valid on every EVM chain.'],
    share_grid: ['Fee-grid split', 'The split shares sit on the documented drainer-as-a-service grid (70, 80, 85 or 90 %).'],
    vanity_drainer: ['Vanity-address drainer', 'A look-alike vanity address that wallets approved or that drained them.'],
    vanity_approval: ['Approval to a vanity address', 'A wallet approved this vanity-address spender.'],
    operator_wallet: ['Operator wallet', 'Payout wallet of two or more flagged drainers.'],
    operator_wallet_multi: ['Operator wallet, strong', 'Payout wallet of several drainers that have their own strong evidence.'],
    serial_deployer: ['Serial deployer', 'Deployed two or more flagged contracts.'],
    serial_deployer_multi: ['Serial deployer, strong', 'Deployed several flagged contracts that have their own strong evidence.'],
    tron_split_capped: ['TRON split without kit code, capped at T3', 'A split pull on TRON with fewer than three victims and no drainer-kit or puller code.'],
    zero_transfer_spoof: ['Zero-value spoof', 'Zero-value transferFrom legs out of other people\'s wallets (address poisoning).'],
    contract_lookups_capped: ['Code lookups capped', 'The per-run limit of code lookups was reached; some code was not checked.'],
  },
  FAMILIES: {},
}

const html = readFileSync(tplPath, 'utf8')
const vocab = {}
for (const name of NAMES) {
  const m = html.match(new RegExp('const ' + name + ' = (\\{[\\s\\S]*?\\});'))
  if (!m) throw new Error(`template.html: const ${name} not found`)
  vocab[name] = Function(`"use strict"; return (${m[1]});`)()
}
for (const [k, add] of Object.entries(EXTRA)) vocab[k] = { ...add, ...vocab[k] }
writeFileSync(out, JSON.stringify(vocab, null, 1) + '\n')
console.log(`vocab: ${Object.keys(vocab.LABELS).length} labels, ${Object.keys(vocab.FAMILIES).length} families -> ${out}`)
