"""Демо-база с ВЫМЫШЛЕННЫМИ данными (домены в зоне .example, аккаунты-пустышки).

Нужна, чтобы показать дашборд и алерты без реальных находок:
    python scripts/make_demo_db.py            # создаёт data/demo.db
    SHIELD_DB=data/demo.db streamlit run dashboard.py
    SHIELD_DB=data/demo.db python -m shield notify --dry-run
"""
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from shield import db  # noqa: E402

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "data/demo.db")
OUT.parent.mkdir(exist_ok=True)
OUT.unlink(missing_ok=True)
con = db.connect(OUT)
now = datetime.now(timezone.utc).replace(microsecond=0)


def ts(days_ago: int) -> str:
    return (now - timedelta(days=days_ago)).isoformat()


DOMAINS = [  # имя, дней назад обнаружен, риск, балл, причины, данные
    ("bcc-secure-login.example", 1, "высокий", 9, ["бренд в имени домена", "зарегистрирован недавно (12 дн. назад)",
        "страница почти копирует официальный сайт (сходство 87%)", "форма ввода пароля"],
        {"created": "2026-11-06", "ips": ["203.0.113.10"], "llm_verdict": "impersonation", "llm_confidence": 0.93}),
    ("bcc-bonus-kz.example", 3, "высокий", 7, ["бренд в имени домена", "зарегистрирован недавно (30 дн. назад)",
        "на странице упоминается банк"], {"created": "2026-10-19", "ips": ["203.0.113.22"]}),
    ("centercredit-pay.example", 5, "средний", 4, ["бренд в имени домена", "свежий SSL-сертификат (2026-11-10)"],
        {"created": "2025-12-01", "ips": ["198.51.100.7"]}),
    ("bcc-online24.example", 8, "средний", 3, ["бренд в имени домена"], {"ips": ["198.51.100.9"]}),
    ("bcc-help.example", 10, "средний", 3, ["бренд в имени домена"], {"ips": []}),
    ("bcc-sale.example", 12, "низкий", 0, ["припаркован / выставлен на продажу / заглушка — может «ожить» позже"],
        {"ips": ["198.51.100.30"]}),
]
TG = [
    ("bcc_support_demo", 2, "высокий", 6, ["имя банка в названии/описании аккаунта", "выдаёт себя за поддержку / службу безопасности",
        "обещает действия со счётом/картой"], {"tg_kind": "bot", "tg_title": "Поддержка (демо)"}),
    ("bcc_cashback_demo", 6, "средний", 4, ["имя банка в username", "бот с именем банка (не официальный)"],
        {"tg_kind": "bot", "tg_title": "Cashback (демо)"}),
]
for name, days, risk, score, why, data in DOMAINS:
    db.upsert(con, "domain", name, data, risk, score, why, ts=ts(days))
for name, days, risk, score, why, data in TG:
    db.upsert(con, "telegram", name, data, risk, score, why, ts=ts(days))
db.set_status(con, "domain", "bcc-help.example", "reviewed", "демо: проверено аналитиком")
db.set_status(con, "domain", "bcc-bonus-kz.example", "reported", "демо: жалоба регистратору отправлена")
con.commit()
print(f"демо-база: {OUT}")
