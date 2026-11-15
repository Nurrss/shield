"""SQLite-хранилище: объекты (домены, аккаунты), их наблюдения и события.

assets       — одна строка на объект; последнее состояние, риск, статус обработки
observations — история наблюдений (что видели при каждом прогоне)
events       — что изменилось: новый объект, риск вырос, сайт изменился, объект исчез
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id          INTEGER PRIMARY KEY,
    kind        TEXT NOT NULL,              -- domain | telegram
    name        TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    risk        TEXT NOT NULL DEFAULT 'низкий',
    score       INTEGER NOT NULL DEFAULT 0,
    reasons     TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'new', -- new | reviewed | reported | removed | false_positive | defensive
    data        TEXT NOT NULL DEFAULT '{}',  -- последнее наблюдение (JSON)
    notes       TEXT NOT NULL DEFAULT '',
    UNIQUE(kind, name)
);
CREATE TABLE IF NOT EXISTS observations (
    id        INTEGER PRIMARY KEY,
    asset_id  INTEGER NOT NULL REFERENCES assets(id),
    ts        TEXT NOT NULL,
    data      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY,
    ts        TEXT NOT NULL,
    asset_id  INTEGER NOT NULL REFERENCES assets(id),
    type      TEXT NOT NULL,                -- new | risk_up | changed | gone
    detail    TEXT NOT NULL DEFAULT '',
    notified  INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS runs (
    id        INTEGER PRIMARY KEY,
    started   TEXT NOT NULL,
    finished  TEXT,
    stats     TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
"""

RISK_ORDER = {"низкий": 0, "средний": 1, "высокий": 2}

# Поля наблюдения, изменение которых считаем значимым («сайт изменился»)
WATCHED_FIELDS = ("ips", "title", "final_url", "http_status", "page_hash", "tg_title", "tg_description")


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def connect(path: str | Path) -> sqlite3.Connection:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    return con


def upsert(con: sqlite3.Connection, kind: str, name: str, data: dict, risk: str, score: int,
           reasons: list[str], ts: str | None = None, defensive: bool = False) -> list[str]:
    """Сохраняет наблюдение. Возвращает список событий, которые оно породило."""
    ts = ts or now()
    events: list[str] = []
    row = con.execute("SELECT * FROM assets WHERE kind=? AND name=?", (kind, name)).fetchone()
    payload = json.dumps(data, ensure_ascii=False, sort_keys=True)
    reasons_s = "; ".join(reasons)
    if row is None:
        status = "defensive" if defensive else "new"
        cur = con.execute(
            "INSERT INTO assets(kind,name,first_seen,last_seen,risk,score,reasons,status,data) VALUES(?,?,?,?,?,?,?,?,?)",
            (kind, name, ts, ts, risk, score, reasons_s, status, payload))
        asset_id = cur.lastrowid
        if not defensive:
            events.append("new")
            con.execute("INSERT INTO events(ts,asset_id,type,detail) VALUES(?,?,?,?)",
                        (ts, asset_id, "new", f"{risk}: {reasons_s}"))
    else:
        asset_id = row["id"]
        old = json.loads(row["data"])
        if RISK_ORDER.get(risk, 0) > RISK_ORDER.get(row["risk"], 0):
            events.append("risk_up")
            con.execute("INSERT INTO events(ts,asset_id,type,detail) VALUES(?,?,?,?)",
                        (ts, asset_id, "risk_up", f"{row['risk']} → {risk}: {reasons_s}"))
        changed = [f for f in WATCHED_FIELDS if old.get(f) != data.get(f) and (old.get(f) or data.get(f))]
        if changed:
            events.append("changed")
            con.execute("INSERT INTO events(ts,asset_id,type,detail) VALUES(?,?,?,?)",
                        (ts, asset_id, "changed", ", ".join(changed)))
        # статус, выставленный человеком (reviewed, reported…), не перетираем
        con.execute("UPDATE assets SET last_seen=?, risk=?, score=?, reasons=?, data=? WHERE id=?",
                    (ts, risk, score, reasons_s, payload, asset_id))
    con.execute("INSERT INTO observations(asset_id,ts,data) VALUES(?,?,?)", (asset_id, ts, payload))
    return events


def mark_gone(con: sqlite3.Connection, kind: str, seen_names: set[str], ts: str | None = None) -> int:
    """Объекты, которые были живы раньше, но не найдены в этом прогоне."""
    ts = ts or now()
    n = 0
    for row in con.execute("SELECT id,name,status FROM assets WHERE kind=?", (kind,)).fetchall():
        if row["name"] not in seen_names and row["status"] not in ("removed", "false_positive"):
            last = con.execute("SELECT type FROM events WHERE asset_id=? ORDER BY id DESC LIMIT 1", (row["id"],)).fetchone()
            if last is None or last["type"] != "gone":
                con.execute("INSERT INTO events(ts,asset_id,type,detail) VALUES(?,?,?,?)",
                            (ts, row["id"], "gone", "больше не резолвится / не найден"))
                n += 1
    return n


def set_status(con: sqlite3.Connection, kind: str, name: str, status: str, note: str = "") -> bool:
    cur = con.execute("UPDATE assets SET status=?, notes=CASE WHEN ?='' THEN notes ELSE ? END WHERE kind=? AND name=?",
                      (status, note, note, kind, name))
    con.commit()
    return cur.rowcount > 0
