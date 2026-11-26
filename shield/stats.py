"""Цифры для питча одним запросом к базе: python -m shield stats."""
from __future__ import annotations

import json

from .collectors import telegram


def collect(con, brand: dict, days: int = 7) -> dict:
    rows = con.execute("SELECT * FROM assets").fetchall()
    doms = [r for r in rows if r["kind"] == "domain"]
    tgs = [r for r in rows if r["kind"] == "telegram"]
    run = con.execute("SELECT stats FROM runs WHERE finished IS NOT NULL ORDER BY id DESC LIMIT 1").fetchone()
    rs = json.loads(run["stats"]) if run else {}
    # «отсеяно анализом»: после проверки страницы это заглушка или посторонний сайт
    filtered = [r for r in doms if "припаркован" in r["reasons"] or "посторонн" in r["reasons"]]
    live = [r for r in rows if r["status"] not in ("defensive", "false_positive", "removed")]
    since = f"-{days} days"
    ev = {r["type"]: r["n"] for r in con.execute(
        "SELECT type, COUNT(*) n FROM events WHERE ts >= datetime('now', ?) GROUP BY type", (since,))}
    return {
        "domain_candidates": rs.get("candidates"),
        "domains_live": len(doms),
        "domains_screenshotted": sum(1 for r in doms if json.loads(r["data"]).get("screenshot")),
        "domains_filtered_by_analysis": len(filtered),
        "domains_llm_checked": sum(1 for r in doms if "llm_verdict" in json.loads(r["data"])),
        "telegram_names_checked": len(telegram.candidates(brand)),
        "telegram_found": len(tgs),
        "high_domains": sum(1 for r in live if r["kind"] == "domain" and r["risk"] == "высокий"),
        "high_telegram": sum(1 for r in live if r["kind"] == "telegram" and r["risk"] == "высокий"),
        "medium_total": sum(1 for r in live if r["risk"] == "средний"),
        f"events_{days}d": ev,
        "statuses": {r["status"]: r["n"] for r in con.execute("SELECT status, COUNT(*) n FROM assets GROUP BY status")},
        "last_run": rs and run is not None,
    }


def render(s: dict, days: int) -> str:
    ev = s[f"events_{days}d"]
    return "\n".join([
        f"Доменов-кандидатов проверено:        {s['domain_candidates']}",
        f"Живых (резолвятся в DNS):            {s['domains_live']}",
        f"  со скриншотом (глубокий анализ):   {s['domains_screenshotted']}",
        f"  отсеяно по содержимому (заглушка/чужой): {s['domains_filtered_by_analysis']}",
        f"  проверено LLM:                     {s['domains_llm_checked']}",
        f"Telegram: имён проверено / найдено:  {s['telegram_names_checked']} / {s['telegram_found']}",
        f"Высокий риск: доменов {s['high_domains']}, Telegram {s['high_telegram']}",
        f"Средний риск (всего):                {s['medium_total']}",
        f"События за {days} дн.: " + (", ".join(f"{k}: {v}" for k, v in ev.items()) or "нет"),
        "Статусы: " + ", ".join(f"{k}: {v}" for k, v in s["statuses"].items()),
    ])
