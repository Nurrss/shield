import io
import json

import pytest
from PIL import Image

from shield import analyze, llm, scoring
from shield.config import load

CFG = load()


def _png(color, size=(320, 200)):
    b = io.BytesIO()
    Image.new("RGB", size, color).save(b, "PNG")
    return b.getvalue()


def test_parse_normalizes():
    d = llm.parse('Ответ: {"verdict": "Impersonation", "confidence": 1.7, "asks_credentials": true, '
                  '"brand_signals": ["логотип"], "reason": "копия входа"}')
    assert d["llm_verdict"] == "impersonation" and d["llm_confidence"] == 1.0 and d["llm_asks_credentials"]


def test_parse_rejects_garbage():
    with pytest.raises(llm.LLMError):
        llm.parse('{"verdict": "maybe"}')


class _Resp:
    status_code = 200

    def __init__(self, payload):
        self._p = payload

    def json(self):
        return self._p


ANSWER = json.dumps({"verdict": "suspicious", "confidence": 0.7, "asks_credentials": True,
                     "brand_signals": [], "reason": "просит код из SMS"})
SHAPES = {
    "gemini": {"candidates": [{"content": {"parts": [{"text": ANSWER}]}}]},
    "openai": {"choices": [{"message": {"content": ANSWER}}]},
    "anthropic": {"content": [{"type": "text", "text": ANSWER}]},
}


@pytest.mark.parametrize("provider", ["gemini", "openai", "anthropic"])
def test_each_provider_roundtrip(provider, monkeypatch):
    sent = {}

    def fake_post(url, **kw):
        sent["url"], sent["kw"] = url, kw
        return _Resp(SHAPES[provider])

    monkeypatch.setattr(llm.requests, "post", fake_post)
    monkeypatch.setenv(CFG.llm["api_key_env"][provider], "test-key")
    cfg = dict(CFG.llm, provider=provider)
    out = llm.verdict(cfg, CFG.brand, "bcc-bonus.site", _png((0, 0, 0)), "Введите код из SMS")
    assert out["llm_verdict"] == "suspicious" and out["llm_provider"].startswith(provider)
    assert "bcc-bonus.site" in json.dumps(sent["kw"]["json"], ensure_ascii=False)


def test_missing_key_is_clear_error(monkeypatch):
    monkeypatch.delenv(CFG.llm["api_key_env"]["gemini"], raising=False)
    with pytest.raises(llm.LLMError, match="GEMINI_API_KEY"):
        llm.verdict(dict(CFG.llm, provider="gemini"), CFG.brand, "x.kz", _png((0, 0, 0)), "")


def test_visual_similarity_identical_and_brand_color():
    green = _png(analyze.BRAND_RGB)
    assert analyze.phash_similarity(green, green) == 1.0
    assert analyze.brand_color_share(green) == 1.0
    assert analyze.brand_color_share(_png((255, 255, 255))) == 0.0


def test_llm_impersonation_raises_risk():
    base = {"created": "2015-01-01", "http_status": 200, "title": "Главная"}
    s0, *_ = scoring.score_domain("bcc-help.com", base, CFG.brand, CFG.scoring, CFG.official_domains)
    s1, lvl, why, _ = scoring.score_domain("bcc-help.com", {**base, "llm_verdict": "impersonation",
                                           "llm_confidence": 0.9, "llm_asks_credentials": True,
                                           "llm_reason": "копия входа"}, CFG.brand, CFG.scoring, CFG.official_domains)
    assert s1 >= s0 + 6 and lvl == "высокий"


def test_llm_unrelated_lowers_risk():
    d = {"created": "2026-10-01", "http_status": 200, "title": "Bcc Books",
         "llm_verdict": "unrelated", "llm_confidence": 0.9, "llm_reason": "книжный магазин"}
    _, lvl, *_ = scoring.score_domain("bcckz.com", d, CFG.brand, CFG.scoring, CFG.official_domains)
    assert lvl != "высокий"
