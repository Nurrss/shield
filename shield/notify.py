"""Алерты в Telegram: новые события из таблицы events → карточка в закрытый канал службы безопасности.

Токен бота и ID канала — только из переменных окружения TELEGRAM_BOT_TOKEN и TELEGRAM_CHAT_ID.
Событие помечается notified=1 только после успешной отправки. События ниже порога риска
помечаются как отправленные без сообщения, чтобы канал не засорялся.
"""
from __future__ import annotations

import html
import json
import logging
import os
import time
from pathlib import Path

import requests

log = logging.getLogger(__name__)

RISK_ORDER = {"низкий": 0, "средний": 1, "высокий": 2}
RISK_ICON = {"высокий": "🔴", "средний": "🟠", "низкий": "⚪"}
EVENT_TITLE = {
    "new": "Новая находка",
    "risk_up": "Риск вырос",
    "changed": "Объект изменился",
    "gone": "Объект исчез",
}
API = "https://api.telegram.org/bot{token}/{method}"
CAPTION_LIMIT = 1024   # лимит Telegram на подпись к фото
TEXT_LIMIT = 4096
PAUSE = 3.0           # секунд между сообщениями: Telegram ограничивает частоту отправки в канал


class NotifyError(RuntimeError):
    pass


def credentials() -> tuple[str, str]:
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat = os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat:
        raise NotifyError("задайте переменные окружения TELEGRAM_BOT_TOKEN и TELEGRAM_CHAT_ID")
    return token, chat


def pending(con, min_risk: str = "средний") -> tuple[list, list]:
    """(к отправке, тихо закрыть). Каждый элемент — строка events JOIN assets."""
    rows = con.execute(
        """SELECT e.id AS event_id, e.ts, e.type, e.detail, a.kind, a.name, a.risk, a.score,
                  a.reasons, a.data, a.status
           FROM events e JOIN assets a ON a.id = e.asset_id
           WHERE e.notified = 0 ORDER BY a.score DESC, e.id""").fetchall()
    send, skip = [], []
    for r in rows:
        ok = RISK_ORDER.get(r["risk"], 0) >= RISK_ORDER[min_risk] and r["status"] != "defensive"
        (send if ok else skip).append(r)
    return send, skip


def _esc(s) -> str:
    return html.escape(str(s), quote=False)


def card(r) -> str:
    """Текст карточки (HTML-разметка Telegram). Реальные данные — только в закрытый канал."""
    d = json.loads(r["data"])
    name = r["name"] if r["kind"] == "domain" else "@" + r["name"]
    # домены «обезвреживаем» (hxxp, [.]), чтобы ссылка не стала кликабельной
    shown = name.replace(".", "[.]") if r["kind"] == "domain" else name
    lines = [f"{RISK_ICON.get(r['risk'], '')} <b>{_esc(EVENT_TITLE.get(r['type'], r['type']))}</b> · "
             f"риск <b>{_esc(r['risk'])}</b> ({r['score']})",
             f"<code>{_esc(shown)}</code> · {'домен' if r['kind'] == 'domain' else 'Telegram'}"]
    if r["kind"] == "domain":
        if d.get("created"):
            lines.append(f"Регистрация: {_esc(d['created'])}")
        if d.get("llm_verdict"):
            lines.append(f"LLM: {_esc(d['llm_verdict'])} ({d.get('llm_confidence', 0):.0%})")
        if d.get("visual_similarity") is not None:
            lines.append(f"Сходство с сайтом банка: {d['visual_similarity']:.0%}")
    else:
        if d.get("tg_title"):
            lines.append(f"Название: {_esc(d['tg_title'])}")
    reasons = [x for x in r["reasons"].split("; ") if x][:6]
    if reasons:
        lines.append("Причины:\n" + "\n".join(f"• {_esc(x)}" for x in reasons))
    if r["type"] != "new" and r["detail"]:
        lines.append(f"Что изменилось: {_esc(r['detail'])[:300]}")
    lines.append("<i>Набор признаков, а не доказанное мошенничество. Не открывать в обычном браузере.</i>")
    return "\n".join(lines)


def screenshot_path(r, base: Path) -> Path | None:
    d = json.loads(r["data"])
    p = d.get("screenshot")
    if not p:
        return None
    p = Path(p)
    p = p if p.is_absolute() else base / p
    return p if p.exists() else None


def _call(token: str, method: str, _retry: bool = True, **kw) -> dict:
    r = requests.post(API.format(token=token, method=method), timeout=30, **kw)
    try:
        j = r.json()
    except ValueError:
        j = {}
    if r.status_code == 429 and _retry:  # слишком часто: ждём сколько просит Telegram и повторяем один раз
        wait = min(int((j.get("parameters") or {}).get("retry_after", 30)) + 1, 90)
        log.info("Telegram просит подождать %d с", wait)
        time.sleep(wait)
        for k, v in kw.get("files", {}).items():
            v.seek(0)
        return _call(token, method, _retry=False, **kw)
    if r.status_code != 200 or not j.get("ok"):
        # токен в сообщение об ошибке не попадает
        raise NotifyError(f"Telegram {method}: {r.status_code} {j.get('description', r.text[:120])}")
    return j


def send_text(token: str, chat: str, text: str) -> None:
    _call(token, "sendMessage", data={"chat_id": chat, "text": text[:TEXT_LIMIT], "parse_mode": "HTML",
                                      "disable_web_page_preview": True})


def send_card(token: str, chat: str, text: str, photo: Path | None) -> None:
    if photo is not None and len(text) <= CAPTION_LIMIT:
        with photo.open("rb") as f:
            _call(token, "sendPhoto", data={"chat_id": chat, "caption": text, "parse_mode": "HTML"},
                  files={"photo": f})
    else:
        send_text(token, chat, text)
        if photo is not None:
            with photo.open("rb") as f:
                _call(token, "sendPhoto", data={"chat_id": chat}, files={"photo": f})


def run(con, base: Path, min_risk: str = "средний", max_cards: int = 20, dry_run: bool = False) -> dict:
    """Отправляет новые события. Возвращает статистику."""
    send, skip = pending(con, min_risk)
    stats = {"to_send": len(send), "quiet": len(skip), "sent": 0, "failed": 0, "dry_run": dry_run}
    cards, rest = send[:max_cards], send[max_cards:]

    if dry_run:
        for r in cards:
            print(card(r), "\n" + "-" * 40)
        if rest:
            print(f"… и ещё {len(rest)} событий в сводке")
        return stats

    token, chat = credentials()
    for r in cards:
        try:
            send_card(token, chat, card(r), screenshot_path(r, base))
            con.execute("UPDATE events SET notified=1 WHERE id=?", (r["event_id"],))
            con.commit()
            stats["sent"] += 1
            time.sleep(PAUSE)
        except (NotifyError, requests.RequestException, OSError) as e:
            log.warning("не отправлено %s: %s", r["name"], e)
            stats["failed"] += 1
    if rest:
        names = ", ".join(r["name"] for r in rest[:15])
        try:
            send_text(token, chat, f"Ещё событий: {len(rest)} (не вошли в карточки). Открой дашборд.\n{_esc(names)}")
            con.executemany("UPDATE events SET notified=1 WHERE id=?", [(r["event_id"],) for r in rest])
            stats["sent"] += len(rest)
        except (NotifyError, requests.RequestException) as e:
            log.warning("сводка не отправлена: %s", e)
            stats["failed"] += len(rest)
    if skip:
        con.executemany("UPDATE events SET notified=1 WHERE id=?", [(r["event_id"],) for r in skip])
    con.commit()
    return stats
