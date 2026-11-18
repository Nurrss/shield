"""LLM-вердикт: «эта страница выдаёт себя за банк?»

Провайдер меняется одной строкой в config.yaml (llm.provider). Вызовы — обычный HTTP (requests),
без SDK, чтобы не зависеть от версий библиотек. Ключ — из переменной окружения.
"""
from __future__ import annotations

import base64
import json
import os
import re
import time

import requests

VERDICTS = ("impersonation", "suspicious", "unrelated", "parked")

PROMPT = """Ты аналитик службы информационной безопасности банка «{brand}» (Казахстан).
Официальные сайты банка: {official}. Перед тобой скриншот и текст страницы с адреса {domain}.

Определи, выдаёт ли страница себя за банк «{brand}» или пытается обмануть его клиентов.
Варианты вердикта:
- "impersonation" — копирует или имитирует банк: его название, логотип, фирменный зелёный цвет, интерфейс,
  вход в интернет-банк, «службу поддержки/безопасности», бонусы или выплаты от имени банка;
- "suspicious" — прямой имитации нет, но есть признаки мошенничества, связанные с банками/финансами
  (сбор паролей, данных карт, кодов из SMS, «разблокировка счёта», «компенсации»);
- "unrelated" — обычный сайт другой организации, банк не имитирует;
- "parked" — пустая страница, заглушка, «домен продаётся», ошибка сервера.

Ответь ТОЛЬКО JSON без пояснений вокруг:
{{"verdict": "...", "confidence": 0.0-1.0, "asks_credentials": true/false,
  "brand_signals": ["что на странице указывает на банк"], "reason": "1–2 предложения по-русски"}}

Текст страницы (обрезан):
---
{text}
---"""


class LLMError(RuntimeError):
    pass


def _key(cfg: dict, provider: str) -> str:
    env = cfg.get("api_key_env", {}).get(provider, "")
    key = os.environ.get(env, "")
    if not key:
        raise LLMError(f"нет ключа: задайте переменную окружения {env}")
    return key


def parse(text: str) -> dict:
    """Достаёт JSON из ответа модели и нормализует поля."""
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise LLMError(f"в ответе нет JSON: {text[:200]}")
    d = json.loads(m.group(0))
    v = str(d.get("verdict", "")).lower().strip()
    if v not in VERDICTS:
        raise LLMError(f"неизвестный вердикт: {v}")
    try:
        conf = max(0.0, min(1.0, float(d.get("confidence", 0))))
    except (TypeError, ValueError):
        conf = 0.0
    return {"llm_verdict": v, "llm_confidence": round(conf, 2),
            "llm_asks_credentials": bool(d.get("asks_credentials", False)),
            "llm_signals": [str(x)[:80] for x in (d.get("brand_signals") or [])][:6],
            "llm_reason": str(d.get("reason", ""))[:300]}


def _gemini(model: str, key: str, prompt: str, img: bytes, timeout: int) -> str:
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    body = {"contents": [{"parts": [{"text": prompt},
                                    {"inline_data": {"mime_type": "image/png", "data": base64.b64encode(img).decode()}}]}],
            "generationConfig": {"temperature": 0, "responseMimeType": "application/json"}}
    r = requests.post(url, params={"key": key}, json=body, timeout=timeout)
    if r.status_code != 200:
        raise LLMError(f"Gemini {r.status_code}: {r.text[:200]}")
    return r.json()["candidates"][0]["content"]["parts"][0]["text"]


def _openai(model: str, key: str, prompt: str, img: bytes, timeout: int) -> str:
    body = {"model": model, "temperature": 0, "response_format": {"type": "json_object"},
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": prompt},
                {"type": "image_url", "image_url": {"url": "data:image/png;base64," + base64.b64encode(img).decode()}}]}]}
    r = requests.post("https://api.openai.com/v1/chat/completions", json=body, timeout=timeout,
                      headers={"Authorization": f"Bearer {key}"})
    if r.status_code != 200:
        raise LLMError(f"OpenAI {r.status_code}: {r.text[:200]}")
    return r.json()["choices"][0]["message"]["content"]


def _anthropic(model: str, key: str, prompt: str, img: bytes, timeout: int) -> str:
    body = {"model": model, "max_tokens": 600, "temperature": 0,
            "messages": [{"role": "user", "content": [
                {"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                             "data": base64.b64encode(img).decode()}},
                {"type": "text", "text": prompt}]}]}
    r = requests.post("https://api.anthropic.com/v1/messages", json=body, timeout=timeout,
                      headers={"x-api-key": key, "anthropic-version": "2023-06-01"})
    if r.status_code != 200:
        raise LLMError(f"Anthropic {r.status_code}: {r.text[:200]}")
    return "".join(c.get("text", "") for c in r.json()["content"])


CALLERS = {"gemini": _gemini, "openai": _openai, "anthropic": _anthropic}


TRANSIENT = re.compile(r"\b(429|500|502|503|504)\b")


def _call_with_retry(fn, model, key, prompt, img, timeout, retries, sleep=time.sleep):
    """Повторяет вызов при временных сбоях провайдера (перегрузка 503, лимит 429, таймаут сети)."""
    for attempt in range(retries):
        try:
            return fn(model, key, prompt, img, timeout)
        except LLMError as e:
            if not TRANSIENT.search(str(e)) or attempt == retries - 1:
                raise
        except requests.RequestException as e:
            if attempt == retries - 1:
                raise LLMError(f"сеть: {type(e).__name__}") from e
        sleep(5 * 2 ** attempt)   # 5, 10, 20 секунд


def verdict(cfg: dict, brand: dict, domain: str, screenshot: bytes, page_text: str) -> dict:
    provider = cfg.get("provider", "none")
    if provider == "none":
        raise LLMError("LLM отключён (llm.provider: none)")
    if provider not in CALLERS:
        raise LLMError(f"неизвестный провайдер {provider}")
    prompt = PROMPT.format(brand=brand["name"], official=", ".join(brand["official_domains"]),
                           domain=domain, text=page_text[:3000])
    raw = _call_with_retry(CALLERS[provider], cfg["models"][provider], _key(cfg, provider), prompt, screenshot,
                           cfg.get("timeout", 60), cfg.get("retries", 4))
    out = parse(raw)
    out["llm_provider"] = f"{provider}:{cfg['models'][provider]}"
    return out
