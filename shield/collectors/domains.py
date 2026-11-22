"""Похожие домены: генерация кандидатов → DNS → RDAP (дата регистрации) → HTTP (что на странице)."""
from __future__ import annotations

import concurrent.futures as cf
import hashlib
import html as _html
import logging
import random
import re
import time
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import dnstwist
import requests

log = logging.getLogger(__name__)
UA = {"User-Agent": "Mozilla/5.0 (compatible; BCC-Shield/0.1; brand-protection research)"}


# ---------- 1. Кандидаты ----------
def generate_candidates(brand: dict) -> set[str]:
    out: set[str] = set()
    for seed in brand["seed_domains"]:
        fz = dnstwist.Fuzzer(seed)
        fz.generate()
        out.update(d["domain"] for d in fz.domains)
    for root in brand["name_roots"]:
        for suf in brand["name_suffixes"]:
            for tld in brand["tlds"]:
                out.add(f"{root}{suf}.{tld}")
    official = {d.lower() for d in brand["official_domains"]} | {d.lower() for d in brand["seed_domains"]}
    return {d.lower() for d in out if d.lower() not in official}


# ---------- 2. DNS ----------
def _resolver(net: dict) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.nameservers = net.get("nameservers") or r.nameservers
    r.timeout = net["dns_timeout"]
    r.lifetime = net["dns_timeout"] * 2
    return r


def resolve_one(name: str, r: dns.resolver.Resolver) -> dict | None:
    """None — домена нет. dict — домен существует. Таймаут повторяем один раз."""
    for attempt in range(2):
        try:
            ips = sorted(x.to_text() for x in r.resolve(name, "A"))
            return {"ips": ips}
        except dns.resolver.NXDOMAIN:
            return None
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            try:
                ns = sorted(x.to_text() for x in r.resolve(name, "NS"))
                return {"ips": [], "ns": ns}
            except Exception:
                return {"ips": [], "ns": []}
        except dns.exception.Timeout:
            if attempt == 1:
                return {"ips": [], "dns_error": "timeout"}
        except Exception as e:  # noqa: BLE001
            log.debug("dns %s: %s", name, e)
            return None
    return None


def resolve_all(names: set[str], net: dict, priority: set[str] | None = None) -> dict[str, dict]:
    """Проверяет имена в DNS с общим лимитом времени (net.dns_budget_s, по умолчанию 20 минут).

    Сначала — уже известные домены (чтобы история не прерывалась), остальные в случайном порядке:
    если DNS медленный и лимит кончился, следующий прогон проверит другую часть.
    resolve_all.complete = False, если проверены не все имена.
    """
    r = _resolver(net)
    budget = net.get("dns_budget_s", 1200)
    prio = priority or set()
    first = sorted(n for n in names if n in prio)
    rest = [n for n in names if n not in prio]
    random.shuffle(rest)
    ordered = first + rest
    found: dict[str, dict] = {}
    done = timeouts = 0
    resolve_all.complete = True
    ex = cf.ThreadPoolExecutor(net["dns_workers"])
    futs = {ex.submit(resolve_one, n, r): n for n in ordered}
    try:
        for f in cf.as_completed(futs, timeout=budget):
            done += 1
            res = f.result()
            if done % 5000 == 0:
                log.info("DNS: проверено %d из %d, живых %d", done, len(ordered), len(found))
            if res is None:
                continue
            if res.get("dns_error"):
                timeouts += 1
                continue
            found[futs[f]] = res
    except cf.TimeoutError:
        resolve_all.complete = False
        log.warning("DNS: лимит %d с исчерпан, проверено %d из %d — остальные в следующий прогон",
                    budget, done, len(ordered))
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    if timeouts:
        log.info("DNS: %d имён ответили таймаутом и пропущены в этом прогоне", timeouts)
    return found


# ---------- 3. RDAP: дата регистрации ----------
def rdap_created(name: str, timeout: int = 15) -> str:
    try:
        j = requests.get(f"https://rdap.org/domain/{name}", timeout=timeout, headers=UA).json()
        ev = {e.get("eventAction"): e.get("eventDate", "")[:10] for e in j.get("events", [])}
        return ev.get("registration", "")
    except Exception:  # noqa: BLE001
        return ""


# ---------- 4. HTTP: что на странице ----------
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.S | re.I)
_FORM_PASS = re.compile(r"type=[\"']?password", re.I)
_CARD = re.compile(r"(card|карт|cvv|cvc|номер карты|pan)", re.I)


def _get_limited(url: str, timeout: int, max_bytes: int = 400_000):
    """GET с общим лимитом времени и размера: сайт, который отдаёт страницу бесконечно, не подвесит прогон."""
    deadline = time.time() + timeout * 2
    with requests.get(url, timeout=timeout, headers=UA, allow_redirects=True, stream=True) as r:
        buf = b""
        for chunk in r.iter_content(16384):
            buf += chunk
            if len(buf) >= max_bytes or time.time() > deadline:
                break
        return r, buf.decode(r.encoding or "utf-8", "ignore")


def http_probe(name: str, page_brand_re: re.Pattern, timeout: int) -> dict:
    out: dict = {}
    for scheme in ("https://", "http://"):
        try:
            r, html = _get_limited(scheme + name, timeout)
            t = _TITLE.search(html)
            out = {
                "http_status": r.status_code,
                "final_url": r.url,
                "title": _html.unescape(re.sub(r"\s+", " ", t.group(1))).strip()[:150] if t else "",
                # имя самого домена на странице («centercredit.ru is for sale») — не упоминание банка
                "mentions_brand": bool(page_brand_re.search(html.lower().replace(name, "").replace(name.split(".")[0], ""))),
                "has_password_form": bool(_FORM_PASS.search(html)),
                "asks_card": bool(_CARD.search(html)) and "<form" in html.lower(),
                "page_hash": hashlib.sha1(html.encode("utf-8", "ignore")).hexdigest()[:16],
            }
            return out
        except Exception as e:  # noqa: BLE001
            out = {"http_error": type(e).__name__}
    return out


def enrich(found: dict[str, dict], brand: dict, net: dict) -> dict[str, dict]:
    page_re = re.compile(brand["page_brand_regex"], re.I)

    def one(name: str) -> tuple[str, dict]:
        d = dict(found[name])
        d["created"] = rdap_created(name)
        d.update(http_probe(name, page_re, net["http_timeout"]))
        return name, d

    with cf.ThreadPoolExecutor(net["http_workers"]) as ex:
        return dict(ex.map(one, list(found)))


def final_host(d: dict) -> str:
    return (urlparse(d.get("final_url", "")).hostname or "").lower()
