"""Telegram-двойники: проверка публичной страницы t.me/<username>.

Ботам и аккаунтам ничего не пишем — только читаем публичную карточку.
"""
from __future__ import annotations

import concurrent.futures as cf
import html
import re

import requests

UA = {"User-Agent": "Mozilla/5.0"}
_OG = lambda prop: re.compile(rf'<meta property="og:{prop}" content="([^"]*)"')  # noqa: E731
_T, _D = _OG("title"), _OG("description")
_EXTRA = re.compile(r'<div class="tgme_page_extra">\s*(.*?)\s*</div>', re.S)


def candidates(brand: dict) -> list[str]:
    names = {(r + s)[:32] for r in brand["telegram_roots"] for s in brand["telegram_suffixes"]}
    return sorted(n for n in names if len(n) >= 5)


def probe(username: str, timeout: int = 15) -> dict | None:
    try:
        t = requests.get(f"https://t.me/{username}", timeout=timeout, headers=UA).text
    except Exception:  # noqa: BLE001
        return None
    title = _T.search(t)
    extra = _EXTRA.search(t)
    title = html.unescape(title.group(1)) if title else ""
    if not title or (title.startswith("Telegram: Contact") and not extra):
        return None  # имени не существует
    extra_s = html.unescape(re.sub(r"\s+", " ", extra.group(1))) if extra else ""
    if "subscriber" in extra_s or "member" in extra_s:
        kind = "channel/group"
    elif username.lower().endswith("bot"):
        kind = "bot"
    else:
        kind = "user"
    desc = _D.search(t)
    return {"tg_kind": kind, "tg_title": title, "tg_extra": extra_s,
            "tg_description": html.unescape(desc.group(1))[:300] if desc else ""}


def scan(brand: dict, workers: int = 20) -> dict[str, dict]:
    names = candidates(brand)
    with cf.ThreadPoolExecutor(workers) as ex:
        res = dict(zip(names, ex.map(probe, names)))
    return {n: v for n, v in res.items() if v}
