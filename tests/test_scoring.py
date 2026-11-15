from datetime import date

from shield import scoring
from shield.config import load

CFG = load()
TODAY = date(2026, 11, 15)
OFF = CFG.official_domains


def sd(name, d):
    return scoring.score_domain(name, d, CFG.brand, CFG.scoring, OFF, today=TODAY)


def test_redirect_to_official_is_defensive():
    s, lvl, why, defensive = sd("mybcc-kz.com", {"final_url": "https://www.bcc.kz/kz/", "created": "2026-09-18"})
    assert defensive and lvl == "низкий"


def test_fresh_brand_domain_is_high():
    s, lvl, why, _ = sd("bcckz.online", {"created": "2026-09-14"})
    assert lvl == "высокий", why


def test_phishing_page_scores_highest():
    s, lvl, why, _ = sd("bcc-login.site", {"created": "2026-11-10", "http_status": 200, "title": "Вход",
                                           "mentions_brand": True, "has_password_form": True})
    assert lvl == "высокий" and s >= 10


def test_unrelated_business_is_downgraded():
    s, lvl, why, _ = sd("bcckz.com", {"created": "2026-06-04", "http_status": 200,
                                      "title": "Bcckz | Books for Music Fans", "mentions_brand": False})
    assert lvl != "высокий", why


def test_old_typo_kz_is_low():
    s, lvl, why, _ = sd("bcg.kz", {"http_status": 200, "title": "Domain Default page"})
    assert lvl == "низкий"


def st(user, d):
    return scoring.score_telegram(user, d, CFG.scoring, CFG.official_telegram, {"centercreditkz"})


def test_official_bot():
    assert st("bankcentercredit_bot", {"tg_title": "Банк ЦентрКредит"})[3] is True


def test_fake_support_bot_high():
    s, lvl, why, _ = st("bcc_bank_bot", {"tg_kind": "bot", "tg_title": "BCC Bank KZ",
                                         "tg_description": "сервис пользования вашим счетом"})
    assert lvl == "высокий", why


def test_unrelated_foreign_account_low():
    s, lvl, why, _ = st("bccsupport", {"tg_kind": "user", "tg_title": "پشتیبانی آنلاین", "tg_description": ""})
    assert lvl == "низкий"


def test_db_events(tmp_path):
    from shield import db
    con = db.connect(tmp_path / "t.db")
    assert db.upsert(con, "domain", "x.kz", {"ips": ["1.1.1.1"]}, "низкий", 1, ["a"]) == ["new"]
    assert db.upsert(con, "domain", "x.kz", {"ips": ["1.1.1.1"]}, "низкий", 1, ["a"]) == []
    ev = db.upsert(con, "domain", "x.kz", {"ips": ["2.2.2.2"], "title": "Вход в БЦК"}, "высокий", 6, ["b"])
    assert ev == ["risk_up", "changed"]
    assert db.mark_gone(con, "domain", set()) == 1


def test_support_username_with_underscore():
    s, lvl, why, _ = st("bcc_support", {"tg_kind": "user", "tg_title": "Bcc_support", "tg_description": ""})
    assert lvl in ("средний", "высокий"), why


def test_foreign_bcc_news_low():
    s, lvl, why, _ = st("bcc_news", {"tg_kind": "channel/group", "tg_title": "BCC中廣新聞網（官方版）"})
    assert lvl == "низкий", why


def test_title_equals_domain_is_parked():
    s, lvl, why, _ = sd("bccbusiness.com", {"created": "2026-05-13", "http_status": 200, "title": "bccbusiness.com"})
    assert lvl == "высокий", why
