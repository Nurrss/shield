import json
import sqlite3

import pytest

from shield import db, notify, takedown

BRAND = {"name": "Банк ЦентрКредит", "official_domains": ["bcc.kz", "centercredit.kz"]}


@pytest.fixture
def con(tmp_path):
    c = db.connect(tmp_path / "t.db")
    db.upsert(c, "domain", "bcc-kz.net", {"ips": ["1.2.3.4"], "created": "2026-02-26"}, "высокий", 6,
              ["бренд в имени домена", "зарегистрирован недавно (2026-02-26, 263 дн. назад)"])
    db.upsert(c, "telegram", "bcc_support", {"tg_title": "Поддержка"}, "высокий", 5,
              ["имя банка в названии/описании аккаунта", "выдаёт себя за поддержку / службу безопасности"])
    db.upsert(c, "domain", "meh.example", {"ips": []}, "низкий", 0, [])
    db.upsert(c, "domain", "bcc.kz.example", {}, "низкий", 0, [], defensive=True)
    c.commit()
    return c


def test_pending_splits_by_risk(con):
    send, skip = notify.pending(con, "средний")
    assert {r["name"] for r in send} == {"bcc-kz.net", "bcc_support"}
    assert {r["name"] for r in skip} == {"meh.example"}  # defensive событий вообще нет


def test_card_defangs_domain_and_escapes_html(con):
    send, _ = notify.pending(con)
    dom = next(r for r in send if r["kind"] == "domain")
    text = notify.card(dom)
    assert "bcc-kz[.]net" in text and "bcc-kz.net" not in text
    assert "<b>Новая находка</b>" in text
    con.execute("UPDATE assets SET reasons=? WHERE name='bcc-kz.net'", ("<script>x</script>",))
    row = notify.pending(con)[0][0]
    assert "<script>" not in notify.card(row)


def test_dry_run_marks_nothing(con, tmp_path, capsys):
    stats = notify.run(con, tmp_path, dry_run=True)
    assert stats["to_send"] == 2 and stats["sent"] == 0
    assert con.execute("SELECT COUNT(*) FROM events WHERE notified=1").fetchone()[0] == 0


def test_run_marks_only_successful(con, tmp_path, monkeypatch):
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "t")
    monkeypatch.setenv("TELEGRAM_CHAT_ID", "c")
    calls = []

    def fake_send(token, chat, text, photo):
        if "bcc_support" in text:
            raise notify.NotifyError("boom")
        calls.append(text)

    monkeypatch.setattr(notify, "send_card", fake_send)
    stats = notify.run(con, tmp_path)
    assert stats["sent"] == 1 and stats["failed"] == 1 and len(calls) == 1
    left = con.execute("SELECT a.name FROM events e JOIN assets a ON a.id=e.asset_id WHERE e.notified=0").fetchall()
    assert [r["name"] for r in left] == ["bcc_support"]  # упавшее останется для повторной отправки


def test_credentials_missing(monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    with pytest.raises(notify.NotifyError):
        notify.credentials()


def test_takedown_all_languages_and_targets(con):
    for kind_name, expected in (("bcc-kz.net", {"registrar", "hosting", "kzcert"}), ("bcc_support", {"telegram", "kzcert"})):
        row = con.execute("SELECT * FROM assets WHERE name=?", (kind_name,)).fetchone()
        for lang in takedown.LANGS:
            msgs = takedown.build(row, BRAND, lang)
            assert {m["target"] for m in msgs} == expected
            for m in msgs:
                assert "{" not in m["body"] and "{" not in m["subject"], (lang, m["target"])  # все поля подставлены
                assert "Банк ЦентрКредит" in m["body"]


def test_takedown_defangs_domain_and_translates(con):
    row = con.execute("SELECT * FROM assets WHERE name='bcc-kz.net'").fetchone()
    en = takedown.build(row, BRAND, "en", ["registrar"], {"registrar_abuse": "abuse@reg.example"})[0]
    assert en["to"] == "abuse@reg.example"
    assert "brand name in the domain name" in en["body"] and "registered recently (2026-02-26)" in en["body"]
    kz = takedown.build(row, BRAND, "kz", ["kzcert"])[0]
    assert kz["to"] == "incident@cert.gov.kz" and "bcc-kz[.]net" in kz["body"]


def test_takedown_missing_abuse_is_marked(con):
    row = con.execute("SELECT * FROM assets WHERE name='bcc-kz.net'").fetchone()
    m = takedown.build(row, BRAND, "ru", ["registrar"], {})[0]
    assert "УКАЖИТЕ АДРЕС ВРУЧНУЮ" in m["to"]


def test_rdap_parsing(monkeypatch):
    class R:
        def __init__(self, j): self._j = j
        def json(self): return self._j

    dom = {"entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Reg Inc"]]],
                         "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@reg.example"]]]}]}]}
    ip = {"name": "NET-1", "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["fn", {}, "text", "Host LLC"],
                                                                                   ["email", {}, "text", "abuse@host.example"]]]}]}
    monkeypatch.setattr(takedown.requests, "get", lambda url, **kw: R(dom if "/domain/" in url else ip))
    c = takedown.rdap_contacts("x.example", ["1.2.3.4"])
    assert c == {"registrar": "Reg Inc", "registrar_abuse": "abuse@reg.example",
                 "host": "Host LLC", "host_abuse": "abuse@host.example"}
