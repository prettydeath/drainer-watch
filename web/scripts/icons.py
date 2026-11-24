"""Render the app icons and the social preview from public/favicon.svg with headless Chromium.
Usage (from web/): python scripts/icons.py   (needs `pip install playwright` + `playwright install chromium`)
Writes public/icon-32.png, apple-touch-icon.png (180), icon-192.png, icon-512.png, icon-maskable-512.png, og.png (1280x640).
"""
import asyncio, pathlib, tempfile
from playwright.async_api import async_playwright

WEB = pathlib.Path(__file__).resolve().parent.parent
PUB = WEB / "public"
SVG = (PUB / "favicon.svg").read_text(encoding="utf8")
FONT = (WEB / "node_modules/@fontsource-variable/source-serif-4/files/source-serif-4-latin-opsz-normal.woff2").as_uri()
FONT_I = (WEB / "node_modules/@fontsource-variable/source-serif-4/files/source-serif-4-latin-opsz-italic.woff2").as_uri()

ICONS = [("icon-32.png", 32, False), ("apple-touch-icon.png", 180, False), ("icon-192.png", 192, False),
         ("icon-512.png", 512, False), ("icon-maskable-512.png", 512, True)]


def icon_html(size, maskable):
    # maskable: full-bleed ink, the mark inside the 80% safe zone; others: the rounded tile itself
    inner = SVG.replace('<rect width="32" height="32" rx="7" fill="#1A2330"/>', "") if maskable else SVG
    pad = round(size * 0.16) if maskable else 0
    return (f'<html><body style="margin:0;background:{"#1A2330" if maskable else "transparent"}">'
            f'<div style="width:{size}px;height:{size}px;box-sizing:border-box;padding:{pad}px">'
            f'{inner.replace("<svg ", f"<svg width=\"{size - 2 * pad}\" height=\"{size - 2 * pad}\" ", 1)}</div></body></html>')


# mini money-flow motif: victims -> drainer -> payout wallets -> exchange
FLOW = """<svg width="400" height="256" viewBox="0 0 470 300" fill="none">
  <g stroke-linecap="butt">
    <path d="M28 40 C140 40 150 150 235 150" stroke="#A8133C" stroke-opacity=".35" stroke-width="10"/>
    <path d="M28 100 C140 100 150 150 235 150" stroke="#A8133C" stroke-opacity=".35" stroke-width="16"/>
    <path d="M28 165 C140 165 150 150 235 150" stroke="#A8133C" stroke-opacity=".35" stroke-width="8"/>
    <path d="M28 230 C140 230 150 150 235 150" stroke="#A8133C" stroke-opacity=".35" stroke-width="22"/>
    <path d="M28 280 C140 280 150 150 235 150" stroke="#A8133C" stroke-opacity=".35" stroke-width="6"/>
    <path d="M235 150 C300 150 310 95 360 95" stroke="#8C99A8" stroke-opacity=".5" stroke-width="40"/>
    <path d="M235 150 C300 150 310 215 360 215" stroke="#8C99A8" stroke-opacity=".5" stroke-width="22"/>
    <path d="M360 95 C410 95 410 150 446 150" stroke="#1D4ED8" stroke-opacity=".45" stroke-width="26"/>
  </g>
  <g fill="#1A2330"><rect x="20" y="30" width="8" height="20"/><rect x="20" y="88" width="8" height="24"/><rect x="20" y="157" width="8" height="16"/>
  <rect x="20" y="215" width="8" height="30"/><rect x="20" y="274" width="8" height="12"/><rect x="229" y="110" width="12" height="80" fill="#A8133C"/>
  <rect x="356" y="72" width="9" height="46"/><rect x="356" y="200" width="9" height="30"/><rect x="442" y="134" width="10" height="32" fill="#1D4ED8"/></g>
</svg>"""

OG = f"""<html><head><style>
@font-face {{ font-family: S; src: url({FONT}) format('woff2'); font-style: normal; font-weight: 200 900; }}
@font-face {{ font-family: S; src: url({FONT_I}) format('woff2'); font-style: italic; font-weight: 200 900; }}
body {{ margin: 0; width: 1280px; height: 640px; background: #E9EDF1; font-family: S, Georgia, serif; color: #1A2330; }}
.card {{ position: absolute; inset: 44px; background: #FBFCFD; border: 1px solid #CBD3DC; border-radius: 3px 10px 10px 10px;
  background-image: repeating-linear-gradient(to bottom, transparent 0, transparent 39px, #DDE4EB 39px, #DDE4EB 40px); }}
.margin {{ position: absolute; left: 92px; top: 0; bottom: 0; width: 2px; background: #9DB0C6; }}
.txt {{ position: absolute; left: 128px; top: 70px; width: 560px; }}
.brand {{ display: flex; gap: 16px; align-items: center; font-size: 26px; color: #4F5B69; font-style: italic; }}
h1 {{ font-size: 92px; line-height: 1; margin: 30px 0 22px; letter-spacing: -.015em; font-weight: 700; }}
p {{ font-size: 30px; line-height: 40px; margin: 0; color: #2B3644; }}
.chains {{ position: absolute; left: 128px; bottom: 54px; font-size: 22px; color: #4F5B69; font-style: italic; }}
.stamp {{ position: absolute; right: 60px; top: 52px; font-size: 22px; font-weight: 800; color: #A8133C; border: 3px solid #A8133C; padding: 2px 12px; border-radius: 6px; transform: rotate(-4deg); }}
.flow {{ position: absolute; right: 52px; top: 196px; }}
</style></head><body><div class="card"><div class="margin"></div>
<div class="txt"><div class="brand">{SVG.replace('<svg ', '<svg width="44" height="44" ', 1)}<span>public case files, updated every few minutes</span></div>
<h1>Drainer Watch</h1><p>Wallet drainers caught on chain: who took the money, where it went, and what can still be frozen.</p></div>
<div class="chains">Ethereum · BNB Chain · Base · TRON</div><div class="stamp">CASE FILES</div><div class="flow">{FLOW}</div>
</div></body></html>"""


async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch()
        for name, size, mask in ICONS:
            pg = await b.new_page(viewport={"width": size, "height": size})
            await pg.set_content(icon_html(size, mask))
            await pg.screenshot(path=str(PUB / name), omit_background=not mask)
            await pg.close()
        pg = await b.new_page(viewport={"width": 1280, "height": 640})
        with tempfile.TemporaryDirectory() as d:  # a file page so the local font loads
            f = pathlib.Path(d) / "og.html"
            f.write_text(OG, encoding="utf8")
            await pg.goto(f.as_uri())
            await pg.evaluate("document.fonts.ready")
            await pg.wait_for_timeout(300)
            await pg.screenshot(path=str(PUB / "og.png"))
        await b.close()
    print("wrote", ", ".join(n for n, *_ in ICONS), "og.png")

asyncio.run(main())
