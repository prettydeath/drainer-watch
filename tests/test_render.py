import json
import logging

from drainerwatch import render
from drainerwatch.util import KeyPool, redact
from tests.helpers import a, make_ctx

TOP_KEYS = {"generated_at", "chains", "totals", "contracts", "drains", "operators", "families", "deployers", "vasps", "daily",
            "clusters"}


def test_embed_escapes_script_terminators():
    payload = {"x": "</script><script>alert(1)</script>", "y": "a b"}
    out = render.embed("<script>const D=/*__DATA__*/null;</script>", payload)
    assert "</script><script>" not in out and "<\\/script>" in out
    assert " " not in out
    body = out.split("const D=")[1].split(";</script>")[0]
    assert json.loads(body.replace("<\\/", "</"))["x"] == payload["x"]       # round-trips after JS unescaping


def test_empty_payload_has_every_key():
    ctx = make_ctx()
    p = render.build_payload(ctx.conn)
    assert set(p) == TOP_KEYS
    assert p["totals"] == {"tiers": {"T1": 0, "T2": 0, "T3": 0}, "victims_24h": 0, "usd_24h": 0, "usd_7d": 0, "drains_24h": 0, "drains_24h_all": 0}
    assert p["contracts"] == [] and p["chains"] == {}


def test_render_all_writes_files(tmp_path):
    ctx = make_ctx()
    ctx.conn.execute("INSERT INTO contracts(chain,address,tier,score,source,labels,first_seen,last_seen,victims,drains,usd) "
                     "VALUES('eth',?,'T2',50,'detector','[\"split_pull\"]','2026-01-01T00:00:00Z','2026-01-02T00:00:00Z',1,1,5)", (a(1),))
    ctx.conn.execute("INSERT INTO evidence(chain,address,type,tx,block,ts,detail) VALUES('eth',?,'split_pull','0xabc',1,1,?)",
                     (a(1), json.dumps({"victims": ["</script>"], "token": a(2), "recipients": []})))
    tpl = tmp_path / "t.html"
    tpl.write_text("<script>window.D=/*__DATA__*/null;</script>", encoding="utf-8")
    site = tmp_path / "site"
    p = render.render_all(ctx.conn, tpl, site, tmp_path / "data")
    html = (site / "index.html").read_text(encoding="utf-8")
    assert "/*__DATA__*/null" not in html and html.count("</script>") == 1       # data cannot close the script tag
    data = json.loads((site / "data.json").read_text(encoding="utf-8"))
    assert set(data) == TOP_KEYS and data["contracts"][0]["address"] == a(1) and p["totals"]["tiers"]["T2"] == 1
    c = data["contracts"][0]
    assert c["deployer"]["via"] == "unknown" and c["deployer"]["address"] is None and c["evidence"][0]["tx"] == "0xabc"


def test_missing_template_writes_data_json_only(tmp_path, caplog):
    ctx = make_ctx()
    site = tmp_path / "site"
    with caplog.at_level(logging.WARNING):
        render.render_all(ctx.conn, tmp_path / "nope.html", site, tmp_path / "data")
    assert (site / "data.json").exists() and not (site / "index.html").exists()
    assert any("template.html missing" in r.message for r in caplog.records)


def test_built_app_replaces_template(tmp_path):
    ctx = make_ctx()
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<div id=root></div>", encoding="utf-8")
    (dist / "assets" / "app.js").write_text("fetch('data.json')", encoding="utf-8")
    (dist / "data.json").write_text("{}", encoding="utf-8")          # a dev copy in dist never overwrites real data
    tpl = tmp_path / "t.html"
    tpl.write_text("<script>window.D=/*__DATA__*/null;</script>", encoding="utf-8")
    site = tmp_path / "site"
    render.render_all(ctx.conn, tpl, site, tmp_path / "data", web_dist=dist)
    assert (site / "index.html").read_text(encoding="utf-8") == "<div id=root></div>"
    assert (site / "assets" / "app.js").exists()
    assert set(json.loads((site / "data.json").read_text(encoding="utf-8"))) == TOP_KEYS


def test_write_if_changed_ignores_generated_at(tmp_path):
    f = tmp_path / "d.json"
    assert render.write_if_changed(f, '{"generated_at": "a", "x": 1}')
    assert not render.write_if_changed(f, '{"generated_at": "b", "x": 1}')
    assert render.write_if_changed(f, '{"generated_at": "b", "x": 2}')


def test_secrets_are_redacted_and_keys_rotate():
    assert "SECRET123" not in redact("Max retries exceeded with url: /v2/api?module=x&apikey=SECRET123&chainid=1")
    assert "SECRET" not in redact("GET /x?token=SECRET failed")
    kp = KeyPool("k1, k2")
    first = kp.next()
    kp.mark_bad(first)
    assert kp.next() != first


def test_template_script_parses(tmp_path):
    """The dashboard script must be valid JS (an unescaped apostrophe in a label string breaks the whole page)."""
    import re
    import shutil
    import subprocess
    import pytest
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    from drainerwatch.constants import TEMPLATE
    js = "\n".join(re.findall(r"<script[^>]*>(.*?)</script>", TEMPLATE.read_text(encoding="utf-8"), re.S))
    f = tmp_path / "t.js"
    f.write_text(js, encoding="utf-8")
    r = subprocess.run([node, "--check", str(f)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[:500]
