"""HTML-отчёт для службы безопасности: карточки угроз со скриншотами и причинами риска.

Один самодостаточный файл (скриншоты встроены), его можно переслать или открыть офлайн.
"""
from __future__ import annotations

import base64
import html
import json
from datetime import date
from pathlib import Path

COLORS = {"высокий": "#c62828", "средний": "#ef6c00", "низкий": "#607d8b"}


def _img(path: str | None, base: Path = Path(".")) -> str:
    if path and not Path(path).is_absolute():
        path = str(base / path)
    if not path or not Path(path).exists():
        return '<div class="noshot">скриншота нет</div>'
    b64 = base64.b64encode(Path(path).read_bytes()).decode()
    return f'<img loading="lazy" src="data:image/png;base64,{b64}">'


def build(con, out: Path, min_risk: str = "средний", brand_name: str = "", base: Path = Path("data")) -> int:
    order = {"низкий": 0, "средний": 1, "высокий": 2}
    rows = [r for r in con.execute(
        "SELECT * FROM assets WHERE status NOT IN ('defensive','false_positive','removed') ORDER BY score DESC")
        if order[r["risk"]] >= order[min_risk]]
    cards = []
    for r in rows:
        d = json.loads(r["data"])
        e = html.escape
        name = e(r["name"]) if r["kind"] == "domain" else "@" + e(r["name"])
        facts = []
        if r["kind"] == "domain":
            if d.get("created"): facts.append(f"регистрация: {e(d['created'])}")
            if d.get("ips"): facts.append("IP: " + e(", ".join(d["ips"][:3])))
            if d.get("llm_verdict"): facts.append(f"LLM: {e(d['llm_verdict'])} ({d.get('llm_confidence', 0):.0%})")
            if d.get("visual_similarity") is not None: facts.append(f"сходство с сайтом банка: {d['visual_similarity']:.0%}")
            shot = _img(d.get("screenshot"), base)
        else:
            facts.append(f"тип: {e(d.get('tg_kind', ''))}")
            facts.append(f"название: {e(d.get('tg_title', ''))}")
            if d.get("tg_extra"): facts.append(e(d["tg_extra"]))
            desc = d.get("tg_description", "")
            if desc.startswith("You can contact") or desc.startswith("You can view and join"):
                desc = ""  # стандартная подпись Telegram
            shot = f'<div class="tg">{e(desc or "без описания")}</div>'
        reasons = "".join(f"<li>{e(x)}</li>" for x in r["reasons"].split("; ") if x)
        cards.append(f"""<article>
  <header><span class="risk" style="background:{COLORS[r['risk']]}">{e(r['risk'])} · {r['score']}</span>
  <h3>{name}</h3><span class="kind">{e(r['kind'])} · {e(r['status'])} · впервые {e(r['first_seen'][:10])}</span></header>
  {shot}
  <p class="facts">{' · '.join(facts)}</p>
  <ul>{reasons}</ul>
</article>""")
    page = f"""<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BCC Shield — отчёт {date.today().isoformat()}</title>
<style>
body{{font:15px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#f4f6f5;color:#1d2321}}
main{{max-width:1180px;margin:0 auto;padding:28px 20px}}
h1{{font-size:24px;margin:0 0 4px}} .sub{{color:#5b6763;margin:0 0 24px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:16px}}
article{{background:#fff;border-radius:12px;padding:14px;box-shadow:0 1px 3px #0001}}
header h3{{margin:6px 0 2px;font-size:17px;word-break:break-all}}
.risk{{color:#fff;font-size:12px;font-weight:600;padding:2px 8px;border-radius:99px}}
.kind{{color:#6b7773;font-size:12px}}
img,.noshot,.tg{{width:100%;aspect-ratio:16/10;object-fit:cover;object-position:top;border-radius:8px;
  border:1px solid #e3e8e6;margin:10px 0 6px;background:#fafbfb}}
.noshot,.tg{{display:flex;align-items:center;justify-content:center;color:#8a9692;font-size:13px;padding:12px;box-sizing:border-box;text-align:center}}
.facts{{font-size:12.5px;color:#4a5552;margin:4px 0}} ul{{margin:6px 0 0;padding-left:18px;font-size:13px}}
.note{{margin-top:28px;font-size:12.5px;color:#6b7773}}
</style></head><body><main>
<h1>BCC Shield — внешние угрозы бренда {html.escape(brand_name)}</h1>
<p class="sub">{date.today().isoformat()} · объектов: {len(rows)} (риск «{min_risk}» и выше)</p>
<div class="grid">{''.join(cards)}</div>
<p class="note">«Высокий риск» — совокупность признаков, а не доказанное мошенничество. Решение принимает аналитик.
Подозрительные сайты открывайте только в изолированной среде.</p>
</main></body></html>"""
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(page, encoding="utf-8")
    return len(rows)
