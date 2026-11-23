"""SQLite storage."""
import json
import sqlite3

from .constants import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS contracts (
    chain TEXT NOT NULL, address TEXT NOT NULL, tier TEXT, score INTEGER, source TEXT, family TEXT,
    labels TEXT, first_seen TEXT, last_seen TEXT, victims INTEGER DEFAULT 0, drains INTEGER DEFAULT 0,
    usd REAL DEFAULT 0, code_hash TEXT, code_size INTEGER, is_contract INTEGER, verified INTEGER, cluster TEXT,
    PRIMARY KEY (chain, address)
);
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT, chain TEXT NOT NULL, address TEXT NOT NULL, type TEXT NOT NULL,
    tx TEXT NOT NULL, block INTEGER, ts INTEGER, detail TEXT,
    UNIQUE (chain, address, type, tx)
);
CREATE INDEX IF NOT EXISTS ix_ev_addr ON evidence(chain, address);
CREATE INDEX IF NOT EXISTS ix_ev_type_ts ON evidence(type, ts);
CREATE TABLE IF NOT EXISTS drains (
    chain TEXT NOT NULL, tx TEXT NOT NULL, log_index INTEGER NOT NULL, ts INTEGER, victim TEXT, drainer TEXT,
    token TEXT, symbol TEXT, decimals INTEGER, amount TEXT, usd REAL, recipient TEXT,
    UNIQUE (chain, tx, log_index)
);
CREATE INDEX IF NOT EXISTS ix_drains_ts ON drains(ts);
CREATE INDEX IF NOT EXISTS ix_drains_drainer ON drains(chain, drainer);
CREATE TABLE IF NOT EXISTS payouts (
    chain TEXT NOT NULL, drainer TEXT NOT NULL, wallet TEXT NOT NULL, role TEXT, share REAL, txs INTEGER DEFAULT 0,
    PRIMARY KEY (chain, drainer, wallet)
);
CREATE INDEX IF NOT EXISTS ix_payouts_wallet ON payouts(chain, wallet);
CREATE TABLE IF NOT EXISTS approvals (
    chain TEXT NOT NULL, owner TEXT NOT NULL, spender TEXT NOT NULL, token TEXT, tx TEXT NOT NULL, block INTEGER,
    ts INTEGER, UNIQUE (chain, owner, spender, token, tx)
);
CREATE INDEX IF NOT EXISTS ix_appr_owner ON approvals(chain, owner);
CREATE INDEX IF NOT EXISTS ix_appr_spender ON approvals(chain, spender);
CREATE TABLE IF NOT EXISTS tokens (chain TEXT NOT NULL, address TEXT NOT NULL, symbol TEXT, decimals INTEGER,
    PRIMARY KEY (chain, address));
CREATE TABLE IF NOT EXISTS codes (
    chain TEXT NOT NULL, address TEXT NOT NULL, code_hash TEXT, size INTEGER, skeleton TEXT, selectors TEXT,
    PRIMARY KEY (chain, address)
);
CREATE TABLE IF NOT EXISTS seeds (
    address TEXT NOT NULL, chain TEXT, label TEXT, source TEXT, added TEXT, UNIQUE (address, chain)
);
CREATE TABLE IF NOT EXISTS verified_cache (       -- Etherscan getsourcecode (ETH); proxies resolved to the implementation
    chain TEXT NOT NULL, address TEXT NOT NULL, verified INTEGER, name TEXT, proxy INTEGER, impl TEXT,
    impl_verified INTEGER, impl_name TEXT, checked_at INTEGER, PRIMARY KEY (chain, address)
);
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);

-- deployer / VASP section
CREATE TABLE IF NOT EXISTS labels (
    chain TEXT NOT NULL, address TEXT NOT NULL, entity TEXT, label TEXT, category TEXT,
    PRIMARY KEY (chain, address)
);
CREATE TABLE IF NOT EXISTS creations (            -- top-level creations seen in the ETH full-block pass (flagged only)
    chain TEXT NOT NULL, address TEXT NOT NULL, deployer TEXT, tx TEXT, block INTEGER, ts INTEGER,
    PRIMARY KEY (chain, address)
);
CREATE TABLE IF NOT EXISTS contract_deployer (
    chain TEXT NOT NULL, address TEXT NOT NULL, deployer TEXT, tx TEXT, via TEXT, factory TEXT, resolved_at INTEGER, block INTEGER,
    PRIMARY KEY (chain, address)
);
CREATE TABLE IF NOT EXISTS deployer_info (
    chain TEXT NOT NULL, address TEXT NOT NULL, funder TEXT, funder_tx TEXT, funder_ts INTEGER, resolved_at INTEGER,
    PRIMARY KEY (chain, address)
);
CREATE TABLE IF NOT EXISTS vasp_links (
    chain TEXT NOT NULL, subject TEXT NOT NULL, subject_role TEXT, counterparty TEXT NOT NULL, kind TEXT NOT NULL,
    entity TEXT, category TEXT, tx TEXT NOT NULL, tx_in TEXT, ts INTEGER, amount TEXT, symbol TEXT, usd REAL,
    confidence TEXT, UNIQUE (chain, subject, counterparty, kind, tx)
);
CREATE TABLE IF NOT EXISTS flows (                -- subject -> X transfers awaiting a forward-to-exchange within 72 h
    chain TEXT NOT NULL, subject TEXT NOT NULL, role TEXT, x TEXT NOT NULL, tx TEXT NOT NULL, block INTEGER,
    ts INTEGER, token TEXT, amount TEXT, usd REAL, UNIQUE (chain, subject, x, tx)
);
CREATE INDEX IF NOT EXISTS ix_flows_x ON flows(chain, x);
CREATE TABLE IF NOT EXISTS alerted (chain TEXT NOT NULL, address TEXT NOT NULL, tier TEXT, sent_at INTEGER,
    PRIMARY KEY (chain, address));
"""


def connect(path=None):
    p = path or DB_PATH
    if str(p) != ":memory:":
        p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=DELETE")   # single-file db: it is published as-is
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(SCHEMA)
    for ddl in ("ALTER TABLE contract_deployer ADD COLUMN block INTEGER",   # migrations for older databases
                "ALTER TABLE contracts ADD COLUMN cluster TEXT",
                "ALTER TABLE contracts ADD COLUMN contract_name TEXT"):
        try:
            conn.execute(ddl)
        except sqlite3.OperationalError:
            pass
    conn.commit()
    return conn


def meta_get(conn, k, default=None):
    r = conn.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
    return r["v"] if r else default


def meta_set(conn, k, v):
    conn.execute("INSERT INTO meta(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, str(v)))


def add_evidence(conn, chain, address, type_, tx, block, ts, detail):
    """Insert-or-ignore. Returns True if new."""
    cur = conn.execute("INSERT OR IGNORE INTO evidence(chain,address,type,tx,block,ts,detail) VALUES(?,?,?,?,?,?,?)",
                       (chain, address, type_, tx, block, ts, json.dumps(detail, ensure_ascii=False, sort_keys=True)))
    return cur.rowcount > 0


