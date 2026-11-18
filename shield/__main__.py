"""CLI: python -m shield <команда>

  run       — прогон мониторинга (по умолчанию всё: домены, сертификаты, Telegram)
  list      — угрозы из базы (по умолчанию средний и высокий риск)
  events    — что изменилось за последние N дней
  analyze   — скриншот + LLM-вердикт для подозрительных доменов
  report    — HTML-отчёт со скриншотами
  rescore   — пересчитать риск без сети
  status    — поменять статус объекта (reviewed / reported / removed / false_positive)
  export    — выгрузить базу в CSV
  notify    — отправить новые события в Telegram-канал (TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID)
  stats     — цифры для питча (воронка, риски, события за неделю)
  takedown  — готовые жалобы на удаление (регистратор, хостинг, Telegram, KZ-CERT) на RU / KZ / EN
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import sys

from . import config as config_mod
from . import db, pipeline


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="shield", description="BCC Shield — мониторинг фейков бренда")
    p.add_argument("--config", help="путь к config.yaml")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="прогон мониторинга")
    r.add_argument("--only", choices=["domains", "certs", "telegram"], action="append",
                   help="запустить только часть сборщиков (можно несколько раз)")
    r.add_argument("--limit", type=int, help="проверить только первые N доменов-кандидатов (для быстрого теста)")
    r.add_argument("--no-analyze", action="store_true", help="без скриншотов и LLM")

    an = sub.add_parser("analyze", help="скриншот + LLM-вердикт для доменов из базы")
    an.add_argument("names", nargs="*", help="конкретные домены (по умолчанию — все подозрительные)")
    an.add_argument("--force", action="store_true", help="анализировать заново, даже если страница не менялась")

    ls = sub.add_parser("list", help="показать угрозы")
    ls.add_argument("--risk", default="средний", choices=["низкий", "средний", "высокий"])
    ls.add_argument("--kind", choices=["domain", "telegram"])

    ev = sub.add_parser("events", help="события за последние дни")
    ev.add_argument("--days", type=int, default=1)

    st = sub.add_parser("status", help="изменить статус объекта")
    st.add_argument("kind", choices=["domain", "telegram"])
    st.add_argument("name")
    st.add_argument("status", choices=["new", "reviewed", "reported", "removed", "false_positive", "defensive"])
    st.add_argument("--note", default="")

    sub.add_parser("rescore", help="пересчитать риск по сохранённым данным (без сети) — после правки весов")

    rp = sub.add_parser("report", help="HTML-отчёт со скриншотами")
    rp.add_argument("path", nargs="?", default="data/report.html")
    rp.add_argument("--risk", default="средний", choices=["низкий", "средний", "высокий"])

    ex = sub.add_parser("export", help="выгрузить в CSV")
    ex.add_argument("path", nargs="?", default="-")

    nt = sub.add_parser("notify", help="алерты в Telegram: новые события → канал")
    nt.add_argument("--min-risk", default="средний", choices=["низкий", "средний", "высокий"])
    nt.add_argument("--max", type=int, default=20, help="максимум карточек за раз, остальное — одной сводкой")
    nt.add_argument("--dry-run", action="store_true", help="только показать, ничего не отправлять и не помечать")

    tk = sub.add_parser("takedown", help="жалоба на удаление объекта")
    tk.add_argument("name", help="домен или @аккаунт")
    tk.add_argument("--lang", default="ru", choices=["ru", "kz", "en"])
    tk.add_argument("--to", action="append", choices=["registrar", "hosting", "telegram", "kzcert"],
                    help="адресат (можно несколько раз); по умолчанию все подходящие")
    tk.add_argument("--offline", action="store_true", help="не искать abuse-адреса в RDAP")

    sx = sub.add_parser("stats", help="цифры для питча")
    sx.add_argument("--days", type=int, default=7)
    sx.add_argument("--json", action="store_true")

    a = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, format="%(asctime)s %(message)s")
    cfg = config_mod.load(a.config)

    if a.cmd == "run":
        only = set(a.only or ["domains", "certs", "telegram"])
        stats = pipeline.run(cfg, do_domains="domains" in only, do_certs="certs" in only,
                             do_telegram="telegram" in only, limit=a.limit, do_analyze=not a.no_analyze)
        print(json.dumps(stats, ensure_ascii=False, indent=2))
        return 0

    con = db.connect(cfg.db_path)
    if a.cmd == "list":
        order = {"низкий": 0, "средний": 1, "высокий": 2}
        q = "SELECT * FROM assets WHERE status NOT IN ('defensive','false_positive','removed')"
        args: list = []
        if a.kind:
            q += " AND kind=?"; args.append(a.kind)
        rows = [x for x in con.execute(q + " ORDER BY score DESC", args) if order[x["risk"]] >= order[a.risk]]
        for x in rows:
            print(f"[{x['risk']:>7}] {x['score']:>3}  {x['kind']:<8} {x['name']:<32} {x['status']:<9} {x['reasons']}")
        print(f"— всего: {len(rows)}")
    elif a.cmd == "events":
        q = """SELECT e.ts, e.type, e.detail, a.kind, a.name, a.risk FROM events e JOIN assets a ON a.id=e.asset_id
               WHERE e.ts >= datetime('now', ?) ORDER BY e.ts DESC"""
        for x in con.execute(q, (f"-{a.days} days",)):
            print(f"{x['ts']}  {x['type']:<8} [{x['risk']}] {x['kind']} {x['name']} — {x['detail']}")
    elif a.cmd == "status":
        ok = db.set_status(con, a.kind, a.name.lstrip("@").lower(), a.status, a.note)
        print("ок" if ok else "объект не найден")
        return 0 if ok else 1
    elif a.cmd == "analyze":
        stats = pipeline.deep_analyze(cfg, con, names=a.names or None, force=a.force)
        print(json.dumps(stats, ensure_ascii=False))
    elif a.cmd == "report":
        from pathlib import Path
        from . import report
        n = report.build(con, Path(a.path), a.risk, cfg.brand["name"], Path(cfg.db_path).parent)
        print(f"отчёт: {a.path} ({n} объектов)")
    elif a.cmd == "rescore":
        from . import scoring
        social = {x.lower() for x in cfg.brand.get("official_social", [])}
        n = 0
        for x in con.execute("SELECT * FROM assets").fetchall():
            d = json.loads(x["data"])
            if x["kind"] == "domain":
                sc, lvl, why, _ = scoring.score_domain(x["name"], d, cfg.brand, cfg.scoring, cfg.official_domains)
            else:
                sc, lvl, why, _ = scoring.score_telegram(x["name"], d, cfg.scoring, cfg.official_telegram, social)
            con.execute("UPDATE assets SET score=?, risk=?, reasons=? WHERE id=?", (sc, lvl, "; ".join(why), x["id"]))
            n += 1
        con.commit()
        print(f"пересчитано: {n}")
    elif a.cmd == "stats":
        from . import stats
        st = stats.collect(con, cfg.brand, a.days)
        print(json.dumps(st, ensure_ascii=False, indent=2) if a.json else stats.render(st, a.days))
    elif a.cmd == "notify":
        from pathlib import Path
        from . import notify
        try:
            stats = notify.run(con, Path(cfg.db_path).parent, a.min_risk, a.max, a.dry_run)
        except notify.NotifyError as e:
            print(f"ошибка: {e}", file=sys.stderr)
            return 2
        print(json.dumps(stats, ensure_ascii=False))
        return 1 if stats["failed"] else 0
    elif a.cmd == "takedown":
        from . import takedown
        name = a.name.lstrip("@").lower()
        row = con.execute("SELECT * FROM assets WHERE name=?", (name,)).fetchone()
        if row is None:
            print("объект не найден в базе (python -m shield list)", file=sys.stderr)
            return 1
        contacts = {}
        if row["kind"] == "domain" and not a.offline:
            ips = json.loads(row["data"]).get("ips") or []
            contacts = takedown.rdap_contacts(name, ips)
        msgs = takedown.build(row, cfg.brand, a.lang, a.to, contacts, cfg.takedown.get("sender", ""))
        print(takedown.render(msgs))
    elif a.cmd == "export":
        cols = ["kind", "name", "risk", "score", "status", "first_seen", "last_seen", "reasons", "data"]
        out = sys.stdout if a.path == "-" else open(a.path, "w", newline="", encoding="utf-8-sig")
        w = csv.writer(out)
        w.writerow(cols)
        for x in con.execute("SELECT * FROM assets ORDER BY score DESC"):
            w.writerow([x[c] for c in cols])
        if out is not sys.stdout:
            out.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
