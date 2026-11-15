"""Логи SSL-сертификатов (Certificate Transparency) через crt.sh.

Новый сертификат с именем бренда часто появляется за часы до запуска фишинга.
crt.sh бывает нестабилен — ошибки не роняют прогон, а попадают в статистику.
"""
from __future__ import annotations

import logging
import time

import requests

log = logging.getLogger(__name__)


def search(patterns: list[str], official: set[str], timeout: int = 60) -> tuple[dict[str, dict], list[str]]:
    found: dict[str, dict] = {}
    failed: list[str] = []
    for p in patterns:
        ok = False
        for attempt in range(3):
            try:
                r = requests.get("https://crt.sh/", params={"q": p, "output": "json", "exclude": "expired"},
                                 timeout=timeout)
                rows = r.json()
                ok = True
                break
            except Exception as e:  # noqa: BLE001
                log.debug("crt.sh %s attempt %d: %s", p, attempt, e)
                time.sleep(3 * (attempt + 1))
        if not ok:
            failed.append(p)
            continue
        for x in rows:
            for n in x.get("name_value", "").split("\n"):
                n = n.lower().strip().lstrip("*.")
                if not n or " " in n or "@" in n or "." not in n:
                    continue
                if any(n == o or n.endswith("." + o) for o in official):
                    continue
                prev = found.get(n)
                nb = x.get("not_before", "")[:10]
                if prev is None or nb > prev["cert_first_seen"]:
                    issuer = x.get("issuer_name", "")
                    found[n] = {"cert_first_seen": nb,
                                "cert_issuer": issuer.split("O=")[-1].split(",")[0] if "O=" in issuer else issuer}
    return found, failed
