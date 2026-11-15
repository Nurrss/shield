"""Глубокий анализ подозрительных доменов: скриншот → визуальное сходство с официальным сайтом → LLM-вердикт.

Безопасность: страницы открываются в headless-браузере в отдельном контексте, без скачивания файлов,
без сохранения cookies. Запускайте на сервере/в контейнере, а не на рабочем ноутбуке.
"""
from __future__ import annotations

import io
import logging
from datetime import date
from pathlib import Path

from . import llm

log = logging.getLogger(__name__)

# Фирменный зелёный БЦК (кнопки, иконки). Доля таких пикселей — дешёвый признак «оформлено под банк».
BRAND_RGB = (0, 170, 110)


class Browser:
    """Один браузер на весь прогон; каждая страница — в чистом контексте."""

    def __init__(self, browser_path: str = "", timeout_s: int = 25):
        from playwright.sync_api import sync_playwright
        self._pw = sync_playwright().start()
        kw = {"args": ["--no-sandbox", "--disable-dev-shm-usage"]}
        if browser_path:
            kw["executable_path"] = browser_path
        self._b = self._pw.chromium.launch(**kw)
        self.timeout = timeout_s * 1000

    def shot(self, url: str) -> dict:
        ctx = self._b.new_context(viewport={"width": 1280, "height": 800}, accept_downloads=False,
                                  ignore_https_errors=True, locale="ru-RU")
        page = ctx.new_page()
        try:
            page.goto(url, timeout=self.timeout, wait_until="domcontentloaded")
            page.wait_for_timeout(2500)
            png = page.screenshot(type="png")
            text = page.inner_text("body", timeout=5000)[:6000]
            return {"png": png, "text": text, "final_url": page.url, "title": page.title()}
        finally:
            ctx.close()

    def close(self) -> None:
        self._b.close()
        self._pw.stop()


def phash_similarity(png_a: bytes, png_b: bytes) -> float:
    """1.0 — картинки практически одинаковые, ~0.5 — ничего общего."""
    import imagehash
    from PIL import Image
    a = imagehash.phash(Image.open(io.BytesIO(png_a)).convert("RGB"), hash_size=16)
    b = imagehash.phash(Image.open(io.BytesIO(png_b)).convert("RGB"), hash_size=16)
    return round(1 - (a - b) / (16 * 16), 3)


def brand_color_share(png: bytes, rgb: tuple[int, int, int] = BRAND_RGB, tol: int = 40) -> float:
    from PIL import Image
    im = Image.open(io.BytesIO(png)).convert("RGB").resize((320, 200))
    px = list(im.getdata())
    hit = sum(1 for p in px if all(abs(p[i] - rgb[i]) <= tol for i in range(3)))
    return round(hit / len(px), 4)


def analyze_domains(names: list[str], cfg, out_dir: Path) -> dict[str, dict]:
    """Возвращает {домен: поля анализа}. Ошибки по одному домену не останавливают остальные."""
    out_dir.mkdir(parents=True, exist_ok=True)
    acfg = cfg.analyze
    import os
    br = Browser(acfg.get("browser_path") or os.environ.get("SHIELD_BROWSER", ""), acfg.get("screenshot_timeout", 25))
    results: dict[str, dict] = {}
    try:
        ref = None
        official = cfg.brand["official_domains"][0]
        try:
            ref = br.shot(f"https://{official}/")["png"]
            (out_dir / f"_reference_{official}.png").write_bytes(ref)
        except Exception as e:  # noqa: BLE001
            log.warning("не удалось снять эталон %s: %s", official, e)
        today = date.today().isoformat()
        for name in names:
            res: dict = {"analyzed_at": today}
            try:
                s = br.shot(f"https://{name}/")
            except Exception:  # noqa: BLE001
                try:
                    s = br.shot(f"http://{name}/")
                except Exception as e:  # noqa: BLE001
                    results[name] = {**res, "analyze_error": f"страница не открылась: {type(e).__name__}"}
                    continue
            path = out_dir / f"{name}_{today}.png"
            path.write_bytes(s["png"])
            res["screenshot"] = str(path)
            res["page_text"] = " ".join(s["text"].split())[:1500]
            res["shot_final_url"] = s["final_url"]
            res["brand_color_share"] = brand_color_share(s["png"])
            if ref is not None:
                res["visual_similarity"] = phash_similarity(ref, s["png"])
            try:
                res.update(llm.verdict(cfg.llm, cfg.brand, name, s["png"], s["text"]))
            except llm.LLMError as e:
                res["llm_error"] = str(e)
            except Exception as e:  # noqa: BLE001
                res["llm_error"] = f"{type(e).__name__}: {e}"[:200]
            results[name] = res
            log.info("анализ %s: %s", name, res.get("llm_verdict", res.get("llm_error", "")))
    finally:
        br.close()
    return results
