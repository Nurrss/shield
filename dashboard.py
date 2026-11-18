"""Дашборд BCC Shield (Streamlit).  Запуск:  streamlit run dashboard.py

Читает ту же базу, что и CLI (data/shield.db или SHIELD_DB). Статусы меняются кнопкой и сразу пишутся в базу.
"""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

from shield import config as config_mod
from shield import db, takedown

st.set_page_config(page_title="BCC Shield", page_icon="🛡️", layout="wide")

cfg = config_mod.load()
BASE = Path(cfg.db_path).parent
RISK_ORDER = {"низкий": 0, "средний": 1, "высокий": 2}
STATUSES = ["new", "reviewed", "reported", "removed", "false_positive", "defensive"]
STATUS_RU = {"new": "новая", "reviewed": "проверена", "reported": "жалоба отправлена", "removed": "удалена",
             "false_positive": "ложное срабатывание", "defensive": "защитная регистрация банка"}


# Streamlit запускает скрипт в разных потоках при каждом действии, поэтому подключение к SQLite
# открываем заново при каждом запуске (это дёшево), а не кэшируем.
con = db.connect(cfg.db_path)


def load_assets() -> pd.DataFrame:
    rows = con.execute("SELECT * FROM assets").fetchall()
    df = pd.DataFrame([dict(r) for r in rows])
    if df.empty:
        return df
    df["risk_n"] = df["risk"].map(RISK_ORDER)
    df["first_day"] = df["first_seen"].str[:10]
    return df


df = load_assets()
st.title("🛡️ BCC Shield")
st.caption(f"Внешние угрозы бренда «{cfg.brand['name']}» · база: {cfg.db_path}")

if df.empty:
    st.warning("База пуста. Выполните `python -m shield run` или скопируйте shield.db в data/.")
    st.stop()

# ---------- сводка ----------
live = df[~df["status"].isin(["defensive", "false_positive", "removed"])]
c1, c2, c3, c4 = st.columns(4)
c1.metric("Объектов в базе", len(df))
c2.metric("Высокий риск", int((live["risk"] == "высокий").sum()))
c3.metric("Средний риск", int((live["risk"] == "средний").sum()))
c4.metric("Жалоба отправлена / удалено", int(df["status"].isin(["reported", "removed"]).sum()))

# ---------- фильтры ----------
with st.sidebar:
    st.header("Фильтры")
    min_risk = st.selectbox("Риск не ниже", ["низкий", "средний", "высокий"], index=1)
    kinds = st.multiselect("Тип", ["domain", "telegram"], default=["domain", "telegram"],
                           format_func=lambda k: "домен" if k == "domain" else "Telegram")
    statuses = st.multiselect("Статус", STATUSES, default=["new", "reviewed", "reported"],
                              format_func=lambda s: STATUS_RU[s])
    q = st.text_input("Поиск по имени")

view = df[(df["risk_n"] >= RISK_ORDER[min_risk]) & df["kind"].isin(kinds) & df["status"].isin(statuses)]
if q:
    view = view[view["name"].str.contains(q, case=False, regex=False)]
view = view.sort_values(["score", "name"], ascending=[False, True]).reset_index(drop=True)

left, right = st.columns([3, 2], gap="large")

with left:
    st.subheader(f"Угрозы ({len(view)})")
    table = view[["risk", "score", "kind", "name", "status", "first_day"]].rename(columns={
        "risk": "риск", "score": "балл", "kind": "тип", "name": "объект", "status": "статус", "first_day": "впервые"})
    sel = st.dataframe(table, width="stretch", hide_index=True, on_select="rerun",
                       selection_mode="single-row", height=420)

    st.subheader("Новые находки по дням")
    daily = df[df["status"] != "defensive"].groupby("first_day").size().rename("новые")
    if len(daily):
        st.bar_chart(daily)

with right:
    st.subheader("Карточка")
    idx = sel.selection.rows[0] if sel and sel.selection.rows else None
    labels = [f"{x.name_} ({x.risk})" for x in view.assign(name_=view["name"]).itertuples()]
    if labels:
        pick = st.selectbox("Открыть объект", range(len(labels)), index=idx if idx is not None and idx < len(labels) else 0,
                            format_func=lambda i: labels[i], key=f"pick-{idx}")
        idx = pick
    if not labels:
        st.info("Нет объектов под выбранные фильтры.")
    else:
        r = view.iloc[idx]
        d = json.loads(r["data"])
        name = r["name"] if r["kind"] == "domain" else "@" + r["name"]
        st.markdown(f"### `{name}`")
        st.markdown(f"**Риск:** {r['risk']} ({r['score']}) · **Статус:** {STATUS_RU[r['status']]}")
        shot = d.get("screenshot")
        if shot:
            p = Path(shot)
            p = p if p.is_absolute() else BASE / p
            if p.exists():
                st.image(str(p), caption="Скриншот (сделан в изолированном браузере)", width="stretch")
        facts = []
        if d.get("created"):
            facts.append(f"регистрация: {d['created']}")
        if d.get("ips"):
            facts.append("IP: " + ", ".join(d["ips"][:3]))
        if d.get("visual_similarity") is not None:
            facts.append(f"сходство с сайтом банка: {d['visual_similarity']:.0%}")
        if d.get("llm_verdict"):
            facts.append(f"LLM: {d['llm_verdict']} ({d.get('llm_confidence', 0):.0%})")
        if r["kind"] == "telegram" and d.get("tg_title"):
            facts.append(f"название: {d['tg_title']}")
        if facts:
            st.caption(" · ".join(facts))
        st.markdown("**Причины риска**")
        for x in [x for x in r["reasons"].split("; ") if x]:
            st.markdown(f"- {x}")
        st.caption("Высокий риск — набор признаков, а не доказанное мошенничество. Решение за аналитиком.")

        note = st.text_input("Заметка", value=r["notes"], key=f"note-{r['id']}")
        st.markdown("**Сменить статус**")
        cols = st.columns(4)
        for col, (stt, label) in zip(cols, [("reviewed", "Проверена"), ("reported", "Жалоба отправлена"),
                                            ("removed", "Удалена"), ("false_positive", "Ложная")]):
            if col.button(label, key=f"{stt}-{r['id']}"):
                db.set_status(con, r["kind"], r["name"], stt, note)
                st.rerun()

        with st.expander("Сформировать жалобу"):
            lang = st.radio("Язык", ["ru", "kz", "en"], horizontal=True, key=f"lang-{r['id']}")
            use_rdap = st.checkbox("Найти abuse-адреса в RDAP (нужен интернет)", value=False, key=f"rdap-{r['id']}")
            if st.button("Сформировать", key=f"tk-{r['id']}"):
                contacts = takedown.rdap_contacts(r["name"], d.get("ips") or []) if (use_rdap and r["kind"] == "domain") else {}
                row = con.execute("SELECT * FROM assets WHERE id=?", (int(r["id"]),)).fetchone()
                msgs = takedown.build(row, cfg.brand, lang, None, contacts, cfg.takedown.get("sender", ""))
                st.session_state[f"msgs-{r['id']}"] = takedown.render(msgs)
            if f"msgs-{r['id']}" in st.session_state:
                text = st.session_state[f"msgs-{r['id']}"]
                st.text_area("Текст жалоб", text, height=320)
                st.download_button("Скачать .txt", text, file_name=f"takedown_{r['name']}_{lang}.txt")
