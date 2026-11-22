"""Один прогон мониторинга: собрать → оценить → сохранить → вернуть, что нового."""
from __future__ import annotations

import json
import logging
import time

from . import db, scoring
from .collectors import certs, domains, telegram
from .config import Config

log = logging.getLogger(__name__)


def deep_analyze(cfg: Config, con, names: list[str] | None = None, force: bool = False) -> dict[str, int]:
    """Скриншот + LLM для подозрительных живых доменов. Повторно анализирует только изменившиеся страницы."""
    from pathlib import Path
    from . import analyze
    acfg = cfg.analyze
    rows = con.execute("SELECT * FROM assets WHERE kind='domain' AND status NOT IN ('defensive','false_positive','removed')"
                       ).fetchall()
    todo = []
    for r in rows:
        d = json.loads(r["data"])
        if names is not None:
            if r["name"] in names:
                todo.append(r)
            continue
        if r["score"] < acfg.get("min_score", 3) or "http_status" not in d:
            continue
        if not force and d.get("analyzed_hash") == d.get("page_hash"):
            continue  # страница не менялась с прошлого анализа
        todo.append(r)
    todo = todo[: acfg.get("max_per_run", 40)]
    if not todo:
        return {"analyzed": 0}
    shots = Path(cfg.db_path).parent / "screenshots"
    res = analyze.analyze_domains([r["name"] for r in todo], cfg, shots)
    stats = {"analyzed": 0, "llm_errors": 0}
    for r in todo:
        a = res.get(r["name"], {})
        d = json.loads(r["data"])
        d.update(a)
        d["analyzed_hash"] = d.get("page_hash")
        sc, lvl, why, defensive = scoring.score_domain(r["name"], d, cfg.brand, cfg.scoring, cfg.official_domains)
        db.upsert(con, "domain", r["name"], d, lvl, sc, why, defensive=defensive)
        stats["analyzed"] += 1
        stats["llm_errors"] += int("llm_error" in a)
    con.commit()
    return stats


def run(cfg: Config, *, do_domains: bool = True, do_certs: bool = True, do_telegram: bool = True,
        limit: int | None = None, do_analyze: bool = True) -> dict:
    con = db.connect(cfg.db_path)
    started = db.now()
    run_id = con.execute("INSERT INTO runs(started) VALUES(?)", (started,)).lastrowid
    con.commit()
    stats: dict = {}
    events: dict[str, int] = {}

    def count(evs: list[str]) -> None:
        for e in evs:
            events[e] = events.get(e, 0) + 1

    # ---- домены (+ сертификаты) ----
    if do_domains or do_certs:
        found: dict[str, dict] = {}
        if do_domains:
            t = time.time()
            cands = domains.generate_candidates(cfg.brand)
            if limit:
                cands = set(sorted(cands)[:limit])
            stats["candidates"] = len(cands)
            log.info("Кандидатов: %d, проверяю DNS…", len(cands))
            found = domains.resolve_all(cands, cfg.network)
            stats["dns_live"] = len(found)
            stats["dns_seconds"] = round(time.time() - t)
        cert_info: dict[str, dict] = {}
        if do_certs:
            cert_info, failed = certs.search(cfg.brand["cert_patterns"], cfg.official_domains)
            stats["cert_names"] = len(cert_info)
            stats["cert_patterns_failed"] = failed
            for name in cert_info:  # имена из сертификатов, которых не было среди кандидатов
                if name not in found:
                    found[name] = {"ips": [], "source": "crt.sh"}
        log.info("Живых доменов: %d, собираю детали…", len(found))
        details = domains.enrich(found, cfg.brand, cfg.network)
        for name, d in details.items():
            d.update(cert_info.get(name, {}))
            prev = con.execute("SELECT data FROM assets WHERE kind='domain' AND name=?", (name,)).fetchone()
            if prev:  # сохраняем результаты прошлого анализа, пока страница не изменилась
                old = json.loads(prev["data"])
                for k, v in old.items():
                    if (k.startswith("llm_") or k in ("visual_similarity", "brand_color_share", "screenshot", "page_text",
                                                      "shot_final_url", "analyzed_at", "analyzed_hash")) and k not in d:
                        d[k] = v
            sc, lvl, why, defensive = scoring.score_domain(name, d, cfg.brand, cfg.scoring, cfg.official_domains)
            count(db.upsert(con, "domain", name, d, lvl, sc, why, defensive=defensive))
        if do_domains and not limit:
            stats["gone_domains"] = db.mark_gone(con, "domain", set(details))
        con.commit()

    # ---- глубокий анализ: скриншот + LLM ----
    if do_analyze and (do_domains or do_certs):
        try:
            stats["deep"] = deep_analyze(cfg, con)
        except Exception as e:  # noqa: BLE001  (нет браузера и т.п. — прогон не падает)
            log.warning("глубокий анализ пропущен: %s", e)
            stats["deep"] = {"error": str(e)[:200]}

    # ---- Telegram ----
    if do_telegram:
        tg = telegram.scan(cfg.brand)
        stats["telegram_found"] = len(tg)
        social = {s.lower() for s in cfg.brand.get("official_social", [])}
        for user, d in tg.items():
            sc, lvl, why, defensive = scoring.score_telegram(user, d, cfg.scoring, cfg.official_telegram, social)
            count(db.upsert(con, "telegram", user.lower(), d, lvl, sc, why, defensive=defensive))
        stats["gone_telegram"] = db.mark_gone(con, "telegram", {u.lower() for u in tg})
        con.commit()

    stats["events"] = events
    con.execute("UPDATE runs SET finished=?, stats=? WHERE id=?",
                (db.now(), json.dumps(stats, ensure_ascii=False), run_id))
    con.commit()
    con.close()
    return stats
