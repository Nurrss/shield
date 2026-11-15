"""Один прогон мониторинга: собрать → оценить → сохранить → вернуть, что нового."""
from __future__ import annotations

import json
import logging
import time

from . import db, scoring
from .collectors import certs, domains, telegram
from .config import Config

log = logging.getLogger(__name__)


def run(cfg: Config, *, do_domains: bool = True, do_certs: bool = True, do_telegram: bool = True,
        limit: int | None = None) -> dict:
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
            sc, lvl, why, defensive = scoring.score_domain(name, d, cfg.brand, cfg.scoring, cfg.official_domains)
            count(db.upsert(con, "domain", name, d, lvl, sc, why, defensive=defensive))
        if do_domains and not limit:
            stats["gone_domains"] = db.mark_gone(con, "domain", set(details))
        con.commit()

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
