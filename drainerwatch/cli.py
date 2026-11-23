"""CLI: python -m drainerwatch <run|loop|render|seeds|backtest>."""
import argparse
import logging
import sys
import time
from collections import Counter

from . import alerts, enrich, rollup, scan, seeds as seedmod
from .constants import CHAINS, DATA_DIR, WA_LOCAL_DEFAULT
from .db import connect
from .prices import Prices
from .render import render_all
from .rpc import Rpc
from .util import env, key_pool, load_env_file, redact

log = logging.getLogger("drainerwatch")


def parse_chains(s):
    out = [c.strip().lower() for c in (s or "eth,bsc,base").split(",") if c.strip()]
    bad = [c for c in out if c not in CHAINS]
    if bad:
        raise SystemExit(f"unknown chain(s): {', '.join(bad)} (choose from {', '.join(CHAINS)})")
    return out


def summarize(conn, stats):
    lines = []
    for ch, st in stats.items():
        if isinstance(st, Exception):
            lines.append(f"{ch}: FAILED {redact(st)}")
            continue
        lines.append(f"{ch}: blocks {st['start']}-{st['done']} ({st['blocks']}), head {st['head']}, lag {st['lag']}, logs {st['logs']}, "
                     f"rpc calls {st['rpc_calls']}, limit hits {st['rpc_limit_hits']}, errors {st['rpc_errors']}, "
                     f"d2 cand/conf {st['d2_candidates']}/{st['d2_confirmed']}, d3 cand/conf {st['d3_candidates']}/"
                     f"{st['d3_confirmed']}, d4 cand {st['d4_candidates']}, tx lookups {st['tx_lookups']}, code lookups "
                     f"{st['code_lookups']}")
    ev = Counter({r["type"]: r["n"] for r in conn.execute("SELECT type,COUNT(*) n FROM evidence GROUP BY type")})
    tiers = Counter({r["tier"]: r["n"] for r in conn.execute("SELECT tier,COUNT(*) n FROM contracts GROUP BY tier")})
    lines.append(f"evidence: {dict(ev)}; tiers: {dict(tiers)}; drains {conn.execute('SELECT COUNT(*) FROM drains').fetchone()[0]}; "
                 f"vasp links {conn.execute('SELECT COUNT(*) FROM vasp_links').fetchone()[0]}")
    return "\n".join(lines)


def do_run(chains, max_blocks, budget_sec, render=True, conn=None, source=None):
    conn = conn or connect()
    t0 = time.monotonic()
    sd = seedmod.refresh(conn)
    enrich.refresh_labels(conn, chains)
    labels = enrich.load_labels(conn)
    prices = Prices(conn)
    prices.refresh()
    stats, rpcs = {}, {}
    scan_budget = budget_sec * 0.85
    for i, ch in enumerate(chains):
        deadline = t0 + scan_budget * (i + 1) / len(chains)
        rpcs[ch] = Rpc(ch)
        try:
            stats[ch] = scan.scan_chain(conn, ch, sd, labels, prices, max_blocks=max_blocks, deadline=deadline, rpc=rpcs[ch],
                                        source=source)
        except Exception as e:  # noqa: BLE001 - one chain failing must not stop the others
            log.error("%s: scan failed: %s", ch, redact(e))
            stats[ch] = e
    rows = rollup.rollup(conn, sd, labels)
    try:
        es = enrich.Etherscan()
        enrich.resolve_deployers(conn, es, rpcs, labels)
        enrich.walk_payouts(conn, es, labels, prices)
        enrich.cross_chain_check(conn, rpcs)
        enrich.lookup_verified(conn, es, rows)
        rows = rollup.rollup(conn, sd, labels)
    except Exception as e:  # noqa: BLE001 - enrichment is best effort
        log.warning("enrichment failed: %s", redact(e))
    try:
        alerts.notify(conn)
    except Exception as e:  # noqa: BLE001
        log.warning("alerts failed: %s", redact(e))
    if render:
        render_all(conn)
    print(summarize(conn, stats))
    return stats


def cmd_run(a):
    do_run(parse_chains(a.chains), a.max_blocks, a.budget_sec, source=a.source)


def cmd_loop(a):
    chains = parse_chains(a.chains)
    while True:
        try:
            do_run(chains, a.max_blocks, a.budget_sec, source=a.source)
        except Exception as e:  # noqa: BLE001
            log.error("run failed: %s", redact(e))
        time.sleep(a.interval)


def cmd_render(a):
    conn = connect()
    render_all(conn)
    print("rendered site/index.html + site/data.json")


def cmd_seeds(a):
    conn = connect()
    sd = seedmod.refresh(conn, force=True)
    c = Counter(r["source"] for r in conn.execute("SELECT source FROM seeds"))
    print(f"seeds: {len(sd)} unique addresses; rows by source {dict(c)}")


def cmd_backtest(a):
    if a.incidents:
        return cmd_backtest_incidents(a)
    if a.from_block is None or a.to_block is None:
        raise SystemExit("backtest: give --from-block/--to-block, or --incidents CSV --split dev|holdout")
    conn = connect(DATA_DIR / "backtest.sqlite")
    sd = seedmod.refresh(conn)
    enrich.refresh_labels(conn, [a.chain])
    labels = enrich.load_labels(conn)
    prices = Prices(conn)
    prices.refresh()
    st = scan.scan_chain(conn, a.chain, sd, labels, prices, deadline=time.monotonic() + a.budget_sec, start=a.from_block,
                         end=a.to_block, persist_cursor=False, source=a.source)
    rollup.rollup(conn, sd, labels)
    print(summarize(conn, {a.chain: st}))


def cmd_backtest_incidents(a):
    import json
    from pathlib import Path
    from . import backtest
    res = backtest.run(Path(a.incidents), a.split, blind=a.blind, window=a.window, budget_sec=a.budget_sec,
                       cache_path=DATA_DIR / "backtest_cache.sqlite", max_components=a.max_components)
    out_dir = Path(a.incidents).parent
    tag = a.split + (f"_{a.tag}" if a.tag else "")
    (out_dir / f"results_{tag}.json").write_text(json.dumps(res, indent=1, default=list), encoding="utf-8")
    base = json.loads(Path(a.baseline).read_text(encoding="utf-8")) if a.baseline else None
    md = backtest.report_md(res, baseline=base, title_extra=f" ({a.tag})" if a.tag else "")
    (out_dir / f"report_{tag}.md").write_text(md, encoding="utf-8")
    m = backtest.metrics(res)
    print(f"{a.split}: incidents {m['n']}, recall T1/T2 {backtest.pct(m['recall_t12'])}, any {backtest.pct(m['recall_any'])}, "
          f"TP addrs {m['tp_addrs']}, FP candidates {m['fp_addrs']} (likely TP {m['fp_likely_tp']}), "
          f"precision {backtest.pct(m['precision'])} / adj {backtest.pct(m['precision_adj'])}; per detector {m['per_det']}")


def cmd_incidents(a):
    from pathlib import Path
    from . import incidents
    conn = connect(DATA_DIR / "incidents_cache.sqlite")
    wa = Path(env("WA_DATA_DIR", WA_LOCAL_DEFAULT)) / "ethereum.csv"
    rows = incidents.build(conn, Path(a.out), wa_path=wa if wa.exists() else None, target_seeds=a.target_seeds,
                           per_seed=a.per_seed, max_seeds_scanned=a.max_scan, budget_sec=a.budget_sec)
    c = Counter(r["split"] for r in rows)
    print(f"incidents: {len(rows)} rows, seeds {len({r['seed_address'] for r in rows})}, splits {dict(c)}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="drainerwatch")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in (("run", cmd_run), ("loop", cmd_loop)):
        s = sub.add_parser(name)
        s.add_argument("--chains", default="eth,bsc,base")
        s.add_argument("--source", choices=["logs", "receipts"], default=None,
                       help="block source for all chains: eth_getLogs or eth_getBlockReceipts (env DRAINERWATCH_SOURCE); "
                            "default per chain: receipts on eth/base (D8, R-A1 active), logs on bsc")
        s.add_argument("--max-blocks", type=int, default=None, help="blocks per chain per run (default eth 100, base 400, bsc 800)")
        s.add_argument("--budget-sec", type=int, default=int(env("DRAINERWATCH_BUDGET_SEC", "300")))
        if name == "loop":
            s.add_argument("--interval", type=int, default=60)
        s.set_defaults(fn=fn)
    sub.add_parser("render").set_defaults(fn=cmd_render)
    sub.add_parser("seeds").set_defaults(fn=cmd_seeds)
    s = sub.add_parser("backtest")
    s.add_argument("--chain", default="eth", choices=list(CHAINS))
    s.add_argument("--from-block", type=int, default=None)
    s.add_argument("--to-block", type=int, default=None)
    s.add_argument("--budget-sec", type=int, default=600)
    s.add_argument("--source", choices=["logs", "receipts"], default=None, help="block source (default env, else per-chain default)")
    s.add_argument("--incidents", default=None, help="incident csv: run the blind incident backtest instead")
    s.add_argument("--split", choices=["dev", "holdout"], default="dev")
    s.add_argument("--blind", action="store_true", help="disable seeds for detection (family lib = dev targets only)")
    s.add_argument("--window", type=int, default=1, help="blocks scanned before/after each incident block")
    s.add_argument("--max-components", type=int, default=None)
    s.add_argument("--tag", default="", help="suffix for results_<split>_<tag>.json / report_<split>_<tag>.md")
    s.add_argument("--baseline", default=None, help="results json to compare against in the report")
    s.add_argument("--env-file", default=None)
    s.set_defaults(fn=cmd_backtest)
    s = sub.add_parser("incidents", help="build the ground-truth incident csv (Etherscan + receipts)")
    s.add_argument("--out", default="tests/backtest/incidents.csv")
    s.add_argument("--target-seeds", type=int, default=60)
    s.add_argument("--per-seed", type=int, default=4)
    s.add_argument("--max-scan", type=int, default=1500)
    s.add_argument("--budget-sec", type=int, default=3600)
    s.add_argument("--env-file", default=None)
    s.set_defaults(fn=cmd_incidents)
    args = p.parse_args(argv)
    if getattr(args, "env_file", None):
        loaded = load_env_file(args.env_file, names={"ETHERSCAN_API_KEYS", "ETH_RPC_URL"})
        log.info("env file: loaded %s", ", ".join(loaded) or "nothing")
    key_pool("ETHERSCAN_API_KEYS")
    args.fn(args)


if __name__ == "__main__":
    main()
