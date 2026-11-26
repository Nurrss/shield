"""Регрессия: каждый найденный домен должен попасть в базу (раньше сохранялся максимум один — ошибка отступа)."""
from shield import config as config_mod
from shield import db, pipeline
from shield.collectors import domains, telegram, certs


def test_run_saves_every_live_domain(tmp_path, monkeypatch):
    cfg = config_mod.load()
    cfg.db_path = str(tmp_path / "t.db")
    names = ["bcc-one.example", "bcc-two.example", "bcc-three.example"]
    monkeypatch.setattr(domains, "generate_candidates", lambda b: set(names))
    monkeypatch.setattr(domains, "resolve_all", lambda c, n, priority=None: {x: {"ips": ["1.1.1.1"]} for x in names})
    monkeypatch.setattr(domains, "enrich", lambda f, b, n: {x: {**f[x], "created": "2026-10-01", "http_status": 200,
                                                              "title": "x", "mentions_brand": False} for x in f})
    monkeypatch.setattr(certs, "search", lambda p, o: ({}, []))
    monkeypatch.setattr(telegram, "scan", lambda b: {})
    stats = pipeline.run(cfg, do_analyze=False)
    con = db.connect(cfg.db_path)
    saved = {r["name"] for r in con.execute("SELECT name FROM assets WHERE kind='domain'")}
    assert saved == set(names)
    assert stats["events"].get("new") == 3


def test_rdap_failure_keeps_known_registration_date(tmp_path, monkeypatch):
    """rdap.org из GitHub Actions часто не отвечает: пустая дата не должна затирать известную и снижать риск."""
    cfg = config_mod.load()
    cfg.db_path = str(tmp_path / "t.db")
    monkeypatch.setattr(domains, "generate_candidates", lambda b: {"bcc-one.example"})
    monkeypatch.setattr(domains, "resolve_all", lambda c, n, priority=None: {"bcc-one.example": {"ips": ["1.1.1.1"]}})
    monkeypatch.setattr(certs, "search", lambda p, o: ({}, []))
    monkeypatch.setattr(telegram, "scan", lambda b: {})
    created = {"v": "2026-10-01"}
    monkeypatch.setattr(domains, "enrich", lambda f, b, n: {x: {**f[x], "created": created["v"], "http_status": 200,
                                                              "title": "x", "mentions_brand": False} for x in f})
    pipeline.run(cfg, do_analyze=False)
    con = db.connect(cfg.db_path)
    first = con.execute("SELECT score, data FROM assets WHERE name='bcc-one.example'").fetchone()
    con.close()
    created["v"] = ""  # RDAP не ответил
    pipeline.run(cfg, do_analyze=False)
    con = db.connect(cfg.db_path)
    second = con.execute("SELECT score, data FROM assets WHERE name='bcc-one.example'").fetchone()
    assert '"created": "2026-10-01"' in second["data"]
    assert second["score"] == first["score"]
