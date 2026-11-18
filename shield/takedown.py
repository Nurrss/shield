"""Шаблоны жалоб на удаление: регистратору домена, хостинг-провайдеру, Telegram, KZ-CERT — на RU / KZ / EN.

    python -m shield takedown bcc-kz.net                 # все подходящие адресаты, русский
    python -m shield takedown bcc-kz.net --lang kz --to registrar

Адреса abuse регистратора и хостера берутся из RDAP (публичные данные). Если не нашли — в письме
остаётся заметная пометка «укажите вручную». Жалобу должен отправлять представитель банка или
человек с его поручения: регистраторы и Telegram обычно требуют подтверждения прав на бренд.
Текст казахской версии желательно показать носителю языка перед отправкой.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import date
from pathlib import Path

import requests

log = logging.getLogger(__name__)
UA = {"User-Agent": "Mozilla/5.0 (compatible; BCC-Shield/0.1; brand-protection research)"}

LANGS = ("ru", "kz", "en")
TARGETS = ("registrar", "hosting", "telegram", "kzcert")

# Постоянные адреса (проверены по официальным источникам, см. README)
KZCERT = {"email": "incident@cert.gov.kz", "phone": "1400", "bot": "@KZ_CERT_chat_bot"}
TELEGRAM = {"email": "abuse@telegram.org", "bot": "@NoToScam"}

MISSING = {"ru": "[УКАЖИТЕ АДРЕС ВРУЧНУЮ — не найден в RDAP]",
           "kz": "[МЕКЕНЖАЙДЫ ҚОЛМЕН КӨРСЕТІҢІЗ — RDAP-та табылмады]",
           "en": "[ENTER ADDRESS MANUALLY — not found in RDAP]"}


# ---------- RDAP: кому писать ----------
def _vcard_get(entity: dict, field: str) -> str:
    arr = (entity.get("vcardArray") or [None, []])[1]
    for item in arr:
        if item and item[0] == field and len(item) >= 4:
            return str(item[3])
    return ""


def _find_entity(j: dict, role: str) -> dict | None:
    for e in j.get("entities", []) or []:
        if role in (e.get("roles") or []):
            return e
        sub = _find_entity(e, role)
        if sub:
            return sub
    return None


def rdap_contacts(domain: str, ips: list[str], timeout: int = 15) -> dict:
    """{'registrar': имя, 'registrar_abuse': email, 'host': имя, 'host_abuse': email}. Пустые строки, если не нашли."""
    out = {"registrar": "", "registrar_abuse": "", "host": "", "host_abuse": ""}
    try:
        j = requests.get(f"https://rdap.org/domain/{domain}", timeout=timeout, headers=UA).json()
        reg = _find_entity(j, "registrar")
        if reg:
            out["registrar"] = _vcard_get(reg, "fn")
            ab = _find_entity(reg, "abuse")
            out["registrar_abuse"] = _vcard_get(ab, "email") if ab else ""
    except Exception as e:  # noqa: BLE001
        log.info("RDAP домен %s: %s", domain, e)
    if ips:
        try:
            j = requests.get(f"https://rdap.org/ip/{ips[0]}", timeout=timeout, headers=UA).json()
            out["host"] = j.get("name", "")
            ab = _find_entity(j, "abuse")
            if ab:
                out["host_abuse"] = _vcard_get(ab, "email")
                out["host"] = _vcard_get(ab, "fn") or out["host"]
        except Exception as e:  # noqa: BLE001
            log.info("RDAP IP %s: %s", ips[0], e)
    return out


# ---------- перевод причин риска (они генерируются по-русски в scoring.py) ----------
_REASONS = [  # (regex на русском, английский, казахский); \1 — первая группа
    (r"^бренд в имени домена", "brand name in the domain name", "домен атауында банк бренді бар"),
    (r"^опечатка официального домена", "typo of the official domain", "ресми доменнің қате жазылуы"),
    (r"^зарегистрирован недавно \((.+?),", r"registered recently (\1)", r"жақында тіркелген (\1)"),
    (r"^свежий SSL-сертификат \((.+?)\)", r"fresh SSL certificate (\1)", r"жаңа SSL-сертификат (\1)"),
    (r"^на странице упоминается банк", "the page mentions the bank", "бетте банк аталады"),
    (r"^форма ввода пароля", "password input form", "құпиясөз енгізу формасы"),
    (r"^форма с данными карты", "card data form", "карта деректерін енгізу формасы"),
    (r"^страница почти копирует", "the page closely copies the official site", "бет ресми сайтқа өте ұқсас"),
    (r"^LLM: имитация банка", "AI review: imitates the bank", "ЖИ талдауы: банкті имитациялайды"),
    (r"^LLM: подозрительно", "AI review: suspicious", "ЖИ талдауы: күдікті"),
    (r"^LLM: страница просит", "AI review: asks for password / card data / codes",
     "ЖИ талдауы: құпиясөз / карта деректерін / кодтарды сұрайды"),
    (r"^имя банка в названии/описании", "bank name in the account name/description",
     "аккаунт атауында/сипаттамасында банк аты бар"),
    (r"^имя банка в username", "bank name in the username", "username-де банк аты бар"),
    (r"^бот с именем банка", "bot named after the bank (not the official one)", "банк атымен аталған бот (ресми емес)"),
    (r"^выдаёт себя за поддержку", "poses as support / security service", "қолдау / қауіпсіздік қызметі болып көрінеді"),
    (r"^обещает действия со счётом", "promises account/card operations", "шотпен/картамен әрекеттерді уәде етеді"),
    (r"^совпадает с официальным хэндлом", "matches the bank's official handle on another social network",
     "банктің басқа әлеуметтік желідегі ресми хэндлімен сәйкес"),
]
_SKIP = re.compile(r"^(сайт не отвечает|в названии другое имя|припаркован)")


def reasons_for(reasons: str, lang: str) -> list[str]:
    items = [x for x in reasons.split("; ") if x and not _SKIP.match(x)]
    if lang == "ru":
        return items
    idx = 1 if lang == "en" else 2
    out = []
    for x in items:
        for pat in _REASONS:
            m = re.match(pat[0], x)
            if m:
                out.append(m.expand(pat[idx]))
                break
        else:
            out.append(x)
    return out


# ---------- тексты ----------
# Заполнители: {brand} {official} {subject_name} {ips} {created} {url} {reasons} {shot} {sender} {today}
T = {
    "ru": {
        "registrar": ("Жалоба: домен {name} — возможная имитация бренда «{brand}»",
            "Здравствуйте!\n\nМы обращаемся от имени «{brand}» (официальные сайты: {official}). "
            "Домен ниже, по нашим данным, может использоваться для имитации банка и обмана его клиентов.\n\n"
            "Домен: {name}\nIP-адрес(а): {ips}\nДата регистрации: {created}\n\n"
            "Выявленные признаки:\n{reasons}\n\n{shot}"
            "Просим проверить домен в соответствии с вашей политикой по злоупотреблениям (abuse policy) и, "
            "если нарушение подтвердится, приостановить делегирование домена. Готовы предоставить "
            "дополнительные доказательства и подтверждение прав на бренд.\n\n"
            "С уважением,\n{sender}\n{today}"),
        "hosting": ("Жалоба: на вашем IP {ips} размещён сайт {name}, возможно имитирующий бренд «{brand}»",
            "Здравствуйте!\n\nНа IP-адресе из вашей сети ({ips}) работает сайт {name}, который, по нашим данным, "
            "может имитировать «{brand}» (официальные сайты: {official}) и вводить клиентов в заблуждение.\n\n"
            "Выявленные признаки:\n{reasons}\n\n{shot}"
            "Просим проверить ресурс по правилам допустимого использования и, при подтверждении, "
            "ограничить доступ к нему.\n\nС уважением,\n{sender}\n{today}"),
        "telegram": ("Impersonation report: {name} / Жалоба на аккаунт, возможно выдающий себя за «{brand}»",
            "Здравствуйте!\n\nАккаунт {name} ({url}) использует название банка «{brand}» "
            "(официальные ресурсы: {official}) и, по нашим данным, может вводить клиентов в заблуждение.\n\n"
            "Выявленные признаки:\n{reasons}\n\n{shot}"
            "Просим проверить аккаунт на нарушение правил Telegram (выдача себя за организацию, мошенничество) "
            "и принять меры. Подтверждение прав на бренд предоставим по запросу.\n\n"
            "С уважением,\n{sender}\n{today}"),
        "kzcert": ("Сообщение об инциденте: имитация бренда «{brand}» — {name}",
            "Здравствуйте!\n\nСообщаем о возможной имитации бренда «{brand}» (официальные сайты: {official}).\n\n"
            "Объект: {name}\n{url_line}Дата регистрации: {created}\nIP-адрес(а): {ips}\n\n"
            "Выявленные признаки:\n{reasons}\n\n{shot}"
            "Просим проверить ресурс и при необходимости принять меры по блокировке / передать обращение "
            "регистратору и хостинг-провайдеру.\n\nС уважением,\n{sender}\n{today}"),
    },
    "kz": {
        "registrar": ("Шағым: {name} домені «{brand}» брендін имитациялауы мүмкін",
            "Сәлеметсіз бе!\n\n«{brand}» АҚ атынан (ресми сайттары: {official}) хабарласып отырмыз. "
            "Төмендегі домен банкті имитациялап, оның клиенттерін алдау үшін қолданылуы мүмкін деп санаймыз.\n\n"
            "Домен: {name}\nIP-мекенжай(лар): {ips}\nТіркелген күні: {created}\n\n"
            "Анықталған белгілер:\n{reasons}\n\n{shot}"
            "Доменді сіздің abuse-саясатыңызға сәйкес тексеруді және бұзушылық расталған жағдайда "
            "доменнің жұмысын тоқтата тұруды сұраймыз. Қосымша дәлелдер мен бренд құқықтарын растайтын "
            "құжаттарды ұсынуға дайынбыз.\n\nҚұрметпен,\n{sender}\n{today}"),
        "hosting": ("Шағым: {ips} IP-мекенжайындағы {name} сайты «{brand}» брендін имитациялауы мүмкін",
            "Сәлеметсіз бе!\n\nСіздің желіңіздегі IP-мекенжайда ({ips}) {name} сайты жұмыс істейді. "
            "Біздің деректеріміз бойынша, ол «{brand}» (ресми сайттары: {official}) брендін имитациялап, "
            "клиенттерді адастыруы мүмкін.\n\nАнықталған белгілер:\n{reasons}\n\n{shot}"
            "Ресурсты пайдалану ережелері бойынша тексеруді және расталған жағдайда қолжетімділікті "
            "шектеуді сұраймыз.\n\nҚұрметпен,\n{sender}\n{today}"),
        "telegram": ("Impersonation report: {name} / «{brand}» атын жамылуы мүмкін аккаунтқа шағым",
            "Сәлеметсіз бе!\n\n{name} аккаунты ({url}) «{brand}» банкінің атын пайдаланады "
            "(ресми ресурстары: {official}) және клиенттерді адастыруы мүмкін.\n\n"
            "Анықталған белгілер:\n{reasons}\n\n{shot}"
            "Аккаунтты Telegram ережелерінің бұзылуына (ұйымның атын жамылу, алаяқтық) тексеруді және "
            "шара қолдануды сұраймыз. Бренд құқықтарының растамасын сұраныс бойынша ұсынамыз.\n\n"
            "Құрметпен,\n{sender}\n{today}"),
        "kzcert": ("Оқиға туралы хабарлама: «{brand}» брендін имитациялау — {name}",
            "Сәлеметсіз бе!\n\n«{brand}» (ресми сайттары: {official}) брендінің ықтимал имитациясы туралы хабарлаймыз.\n\n"
            "Нысан: {name}\n{url_line}Тіркелген күні: {created}\nIP-мекенжай(лар): {ips}\n\n"
            "Анықталған белгілер:\n{reasons}\n\n{shot}"
            "Ресурсты тексеруді және қажет болса бұғаттау шараларын қабылдауды / өтінішті тіркеушіге және "
            "хостинг-провайдерге жолдауды сұраймыз.\n\nҚұрметпен,\n{sender}\n{today}"),
    },
    "en": {
        "registrar": ("Abuse report: domain {name} may impersonate the brand «{brand}»",
            "Hello,\n\nWe are writing on behalf of «{brand}» (official websites: {official}). "
            "The domain below may be used to impersonate the bank and mislead its customers.\n\n"
            "Domain: {name}\nIP address(es): {ips}\nRegistration date: {created}\n\n"
            "Indicators:\n{reasons}\n\n{shot}"
            "Please review the domain under your abuse policy and, if the violation is confirmed, "
            "suspend it. We can provide further evidence and proof of our rights to the brand.\n\n"
            "Regards,\n{sender}\n{today}"),
        "hosting": ("Abuse report: site {name} on your IP {ips} may impersonate «{brand}»",
            "Hello,\n\nThe website {name} hosted on an IP address in your network ({ips}) may impersonate "
            "«{brand}» (official websites: {official}) and mislead customers.\n\n"
            "Indicators:\n{reasons}\n\n{shot}"
            "Please review it under your acceptable use policy and, if confirmed, restrict access.\n\n"
            "Regards,\n{sender}\n{today}"),
        "telegram": ("Impersonation report: {name} may impersonate «{brand}»",
            "Hello,\n\nThe account {name} ({url}) uses the name of the bank «{brand}» "
            "(official resources: {official}) and may mislead its customers.\n\n"
            "Indicators:\n{reasons}\n\n{shot}"
            "Please review the account for violations of Telegram's Terms of Service (impersonation of an "
            "organization, scam) and take action. Proof of brand ownership available on request.\n\n"
            "Regards,\n{sender}\n{today}"),
        "kzcert": ("Incident report: impersonation of «{brand}» — {name}",
            "Hello,\n\nWe report possible impersonation of «{brand}» (official websites: {official}).\n\n"
            "Resource: {name}\n{url_line}Registration date: {created}\nIP address(es): {ips}\n\n"
            "Indicators:\n{reasons}\n\n{shot}"
            "Please review the resource and, if necessary, take blocking measures and/or forward the report "
            "to the registrar and hosting provider.\n\nRegards,\n{sender}\n{today}"),
    },
}
SHOT = {"ru": "Скриншот страницы (сделан в изолированной среде): {f}\n\n",
        "kz": "Беттің скриншоты (оқшауланған ортада жасалған): {f}\n\n",
        "en": "Screenshot of the page (taken in an isolated environment): {f}\n\n"}
URL_LINE = {"ru": "Ссылка: {u}\n", "kz": "Сілтеме: {u}\n", "en": "Link: {u}\n"}
SENDER_DEFAULT = {"ru": "[Ваше имя, должность, контакты]", "kz": "[Аты-жөніңіз, лауазымыңыз, байланыс]",
                  "en": "[Your name, position, contacts]"}


def targets_for(kind: str) -> list[str]:
    return ["telegram", "kzcert"] if kind == "telegram" else ["registrar", "hosting", "kzcert"]


def _defang(s: str) -> str:
    return s.replace(".", "[.]")


def build(row, brand: dict, lang: str = "ru", targets: list[str] | None = None, contacts: dict | None = None,
          sender: str = "") -> list[dict]:
    """Список писем: {'target', 'to', 'subject', 'body', 'note'}. row — строка таблицы assets."""
    if lang not in LANGS:
        raise ValueError(f"язык: {', '.join(LANGS)}")
    d = json.loads(row["data"])
    kind, name = row["kind"], row["name"]
    contacts = contacts or {}
    shown = name if kind == "domain" else "@" + name
    url = f"https://t.me/{name}" if kind == "telegram" else d.get("final_url") or f"http://{name}"
    shot = d.get("screenshot")
    ctx = {
        "brand": brand["name"], "official": ", ".join(brand["official_domains"]),
        "name": shown, "ips": ", ".join(d.get("ips") or []) or "—", "created": d.get("created") or "—",
        "url": _defang(url) if kind == "domain" else url,
        "url_line": URL_LINE[lang].format(u=_defang(url) if kind == "domain" else url),
        "reasons": "\n".join("• " + x for x in reasons_for(row["reasons"], lang)) or "—",
        "shot": SHOT[lang].format(f=Path(shot).name) if shot else "",
        "sender": sender or SENDER_DEFAULT[lang], "today": date.today().isoformat(),
    }
    out = []
    for t in targets or targets_for(kind):
        subj, body = T[lang][t]
        note = ""
        if t == "registrar":
            to = contacts.get("registrar_abuse") or MISSING[lang]
            note = contacts.get("registrar", "")
        elif t == "hosting":
            to = contacts.get("host_abuse") or MISSING[lang]
            note = contacts.get("host", "")
        elif t == "telegram":
            to = TELEGRAM["email"]
            note = f"также через бота {TELEGRAM['bot']} (Report Impersonation)"
        else:
            to = KZCERT["email"]
            note = f"тел. {KZCERT['phone']} (бесплатно, круглосуточно), Telegram {KZCERT['bot']}"
        text = re.sub(r"^[^\n]*: —\n", "", body.format(**ctx), flags=re.M)  # пустые поля (у аккаунта нет IP/даты)
        out.append({"target": t, "to": to, "subject": subj.format(**ctx), "body": text, "note": note})
    return out


def render(msgs: list[dict]) -> str:
    parts = []
    for m in msgs:
        note = f"   ({m['note']})" if m["note"] else ""
        parts.append(f"{'=' * 70}\nКому: {m['to']}{note}\nТема: {m['subject']}\n{'-' * 70}\n{m['body']}\n")
    return "\n".join(parts)
