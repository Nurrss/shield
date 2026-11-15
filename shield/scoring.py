"""Оценка риска. Чистые функции: на вход — наблюдение, на выход — балл, уровень, причины.

Принцип: риск = сумма объяснимых признаков. Каждая причина видна аналитику,
поэтому оценку можно оспорить и поправить веса в одном месте.
"""
from __future__ import annotations

import re
from datetime import date, datetime

PARKED = ("parked", "for sale", "forsale", "default page", "caddy works", "domain is for sale", "お名前.com",
          "припаркован", "coming soon", "launching soon", "index of /", "welcome to nginx", "it works!",
          "продается", "продаётся", "приобрести этот домен", "buy this domain", "registration has expired",
          "renew this domain", "сайт успешно размещен", "domain may be for sale", "hugedomains", "sedo")


def _days_since(iso: str, today: date | None = None) -> int | None:
    if not iso:
        return None
    try:
        d = datetime.strptime(iso[:10], "%Y-%m-%d").date()
    except ValueError:
        return None
    return ((today or date.today()) - d).days


def level(score: int, cfg: dict) -> str:
    if score >= cfg["high"]:
        return "высокий"
    if score >= cfg["medium"]:
        return "средний"
    return "низкий"


def is_defensive(final_host: str, official: set[str]) -> bool:
    return any(final_host == o or final_host.endswith("." + o) for o in official)


def score_domain(name: str, d: dict, brand: dict, cfg: dict, official: set[str],
                 today: date | None = None) -> tuple[int, str, list[str], bool]:
    """Возвращает (балл, уровень, причины, защитный_ли)."""
    from urllib.parse import urlparse
    fh = (urlparse(d.get("final_url", "")).hostname or "").lower()
    if fh and is_defensive(fh, official):
        return -10, "низкий", ["редирект на официальный сайт — вероятно, защитная регистрация самим банком"], True

    s, why = 0, []
    brand_re = re.compile(brand["brand_regex"], re.I)
    if brand_re.search(name.split(".")[0]) and len(name.split(".")[0]) > 3:
        s += 3; why.append("бренд в имени домена")
    elif name.endswith(".kz"):
        s += 1; why.append("опечатка официального домена в зоне .kz")

    age = _days_since(d.get("created", ""), today)
    if age is not None and age <= cfg["fresh_days"]:
        s += 3; why.append(f"зарегистрирован недавно ({d['created']}, {age} дн. назад)")
    elif age is not None and age <= 2 * cfg["fresh_days"]:
        s += 1; why.append(f"зарегистрирован {d['created']}")

    cert_age = _days_since(d.get("cert_first_seen", ""), today)
    if cert_age is not None and cert_age <= 30:
        s += 2; why.append(f"свежий SSL-сертификат ({d['cert_first_seen']})")

    mentions = bool(d.get("mentions_brand"))
    if d.get("page_text") is not None:  # после скриншота: текст страницы без упоминаний самого адреса
        txt = d["page_text"].lower().replace(name, "").replace(name.split(".")[0], "")
        mentions = bool(re.search(brand["page_brand_regex"], txt, re.I))
    d = {**d, "mentions_brand": mentions}
    if mentions:
        s += 3; why.append("на странице упоминается банк")
        if d.get("has_password_form"):
            s += 2; why.append("форма ввода пароля")
        if d.get("asks_card"):
            s += 2; why.append("форма с данными карты")

    title = (d.get("title") or "").lower()
    page = (d.get("page_text") or "").lower() + " " + (d.get("shot_final_url") or "").lower()
    shot_host = (urlparse(d.get("shot_final_url", "")).hostname or "").lower().removeprefix("www.")
    foreign_redirect = (shot_host and shot_host != name and not shot_host.endswith("." + name)
                        and not re.search(brand["brand_regex"], shot_host, re.I)
                        and not any(k in shot_host for k in ("godaddy", "sedo", "dan.com", "afternic", "namecheap")))
    if any(p in title or p in page for p in PARKED) or title.strip() in (name, "www." + name):
        why.append("припаркован / выставлен на продажу / заглушка — может «ожить» позже")
        if d.get("page_text") is not None and not d.get("mentions_brand"):
            # подтверждено скриншотом: сейчас там нет ничего от банка → «наблюдать», а не «срочно реагировать»
            parked_cap = cfg["high"] - 1
            s = min(s - 1, parked_cap)
    elif foreign_redirect and not d.get("mentions_brand"):
        s -= 3; why.append(f"перенаправляет на посторонний сайт ({shot_host})")
    elif "http_status" not in d:
        why.append("сайт не отвечает (возможен геофильтр — проверить из Казахстана)")
    elif title and not d.get("mentions_brand") and d.get("http_status", 0) < 400:
        s -= 2; why.append(f"на сайте посторонний контент («{d.get('title', '')[:50]}»)")

    # --- результаты глубокого анализа (скриншот + LLM), если он был ---
    sim = d.get("visual_similarity")
    if sim is not None and sim >= 0.85:
        s += 4; why.append(f"страница почти копирует официальный сайт (сходство {sim:.0%})")
    v, conf = d.get("llm_verdict"), d.get("llm_confidence", 0)
    if v == "impersonation" and conf >= 0.6:
        s += 4; why.append(f"LLM: имитация банка ({conf:.0%}) — {d.get('llm_reason', '')}")
    elif v == "impersonation" or v == "suspicious":
        s += 2; why.append(f"LLM: подозрительно ({conf:.0%}) — {d.get('llm_reason', '')}")
    elif v == "unrelated" and conf >= 0.6:
        s -= 3; why.append(f"LLM: посторонний сайт — {d.get('llm_reason', '')}")
    if d.get("llm_asks_credentials") and v in ("impersonation", "suspicious"):
        s += 2; why.append("LLM: страница просит пароль / данные карты / коды")

    return s, level(s, cfg), why, False


TG_BRAND = re.compile(r"центр\s*кредит|centercredit|center\s*credit|(?<![a-z])bcc(?![a-z])|bcc[\s_.-]?(bank|kz)", re.I)
# Названия на других письменностях (китайский, арабский/фарси, азербайджанский латинский с ə и т.п.)
FOREIGN = re.compile(r"[\u0600-\u06FF\u4E00-\u9FFF\u3040-\u30FF\u0590-\u05FFəğşı]")


def score_telegram(username: str, d: dict, cfg: dict, official_tg: set[str],
                   official_instagram: set[str] | None = None) -> tuple[int, str, list[str], bool]:
    if username.lower() in official_tg:
        return -10, "низкий", ["официальный аккаунт банка"], True
    title, desc, kind = d.get("tg_title", ""), d.get("tg_description", ""), d.get("tg_kind", "")
    if re.match(r"You can (contact|view and join)", desc):
        desc = ""  # стандартная подпись Telegram с username — не сигнал
    s, why = 0, []
    brand = bool(TG_BRAND.search(f"{title} {desc}"))
    brand_in_username = bool(TG_BRAND.search(username.replace("_", " ")))
    if brand:
        s += 3; why.append("имя банка в названии/описании аккаунта")
    elif brand_in_username:
        s += 2; why.append("имя банка в username")
        if title and not re.search(r"bcc|centercredit|центр|поддержк|support|банк|bank", title, re.I):
            s -= 1; why.append(f"в названии другое имя («{title[:40]}»)")
    if brand or brand_in_username:
        if kind == "bot":
            s += 1; why.append("бот с именем банка (официальные: " + ", ".join("@" + o for o in sorted(official_tg)) + ")")
        if re.search(r"поддержк|support|служб|security|безопасн", f"{title} {username}", re.I):
            s += 2; why.append("выдаёт себя за поддержку / службу безопасности")
        if re.search(r"сч[её]т|account|оплат|перевод|карт", desc, re.I):
            s += 2; why.append("обещает действия со счётом/картой")
    else:
        s -= 3; why.append("не связан с банком (другой бренд или язык)")
    if (brand or brand_in_username) and FOREIGN.search(f"{title} {desc}"):
        s -= 3; why.append("название на другом языке — вероятно, посторонний бренд с аббревиатурой BCC")
    if official_instagram and username.lower() in official_instagram:
        s += 2; why.append("совпадает с официальным хэндлом банка в другой соцсети")
    return s, level(s, cfg), why, False
