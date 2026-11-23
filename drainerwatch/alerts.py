"""Optional Telegram alerts on NEW T1/T2 contracts. No TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID -> no-op.
The bot token is never logged (only HTTP status)."""
import html
import logging

import requests

from .constants import CHAINS
from .util import env, iso, now_ts, parse_iso

log = logging.getLogger("drainerwatch.alerts")
MAX_PER_RUN = 10
FRESH_SEC = 6 * 3600          # history is never replayed: only recently active contracts alert


def configured():
    return bool(env("TELEGRAM_BOT_TOKEN") and env("TELEGRAM_CHAT_ID"))


def send_message(text):
    r = requests.post(f"https://api.telegram.org/bot{env('TELEGRAM_BOT_TOKEN')}/sendMessage",
                      json={"chat_id": env("TELEGRAM_CHAT_ID"), "text": text, "parse_mode": "HTML",
                            "disable_web_page_preview": True}, timeout=20)
    r.raise_for_status()


def format_message(c, evidence):
    e = lambda x: html.escape(str(x), quote=False)  # noqa: E731
    ex = CHAINS[c["chain"]]["explorer"]
    lines = [f"<b>{e(c['tier'])} drainer candidate</b> on {e(c['chain'])} (score {c['score']})",
             f"<code>{e(c['address'])}</code>", f"{ex}/address/{e(c['address'])}",
             f"labels: {e(', '.join(c['labels']))}; victims {c['victims']}; drains {c['drains']}; usd {c['usd']}"]
    for ev in evidence[:3]:
        lines.append(f"{e(ev['type'])}: {ex}/tx/{e(ev['tx'])}")
    dash = env("DASHBOARD_URL")
    if dash:
        lines.append(e(dash))
    return "\n".join(lines)


def notify(conn, now=None):
    """Send alerts for fresh, not yet alerted T1/T2 contracts. Returns the number sent."""
    if not configured():
        return 0
    now = now or now_ts()
    rows = conn.execute("SELECT c.* FROM contracts c LEFT JOIN alerted a ON a.chain=c.chain AND a.address=c.address "
                        "WHERE c.tier IN ('T1','T2') AND a.address IS NULL ORDER BY c.tier, c.score DESC").fetchall()
    sent = 0
    for r in rows:
        if now - (parse_iso(r["last_seen"]) or 0) > FRESH_SEC:
            continue
        if sent >= MAX_PER_RUN:
            break
        import json
        ev = [dict(type=x["type"], tx=x["tx"]) for x in conn.execute(
            "SELECT type,tx FROM evidence WHERE chain=? AND address=? ORDER BY ts DESC LIMIT 3", (r["chain"], r["address"]))]
        c = dict(r, labels=json.loads(r["labels"] or "[]"))
        try:
            send_message(format_message(c, ev))
        except requests.RequestException as e:
            log.warning("telegram send failed (%s)", type(e).__name__)
            break
        conn.execute("INSERT OR REPLACE INTO alerted(chain,address,tier,sent_at) VALUES(?,?,?,?)",
                     (r["chain"], r["address"], r["tier"], now))
        sent += 1
    conn.commit()
    return sent
