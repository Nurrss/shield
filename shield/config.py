from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Config:
    brand: dict
    scoring: dict
    network: dict
    analyze: dict = field(default_factory=dict)
    llm: dict = field(default_factory=dict)
    takedown: dict = field(default_factory=dict)
    db_path: Path = field(default_factory=lambda: Path(os.environ.get("SHIELD_DB", ROOT / "data" / "shield.db")))

    @property
    def official_domains(self) -> set[str]:
        return {d.lower() for d in self.brand["official_domains"]}

    @property
    def official_telegram(self) -> set[str]:
        return {u.lower() for u in self.brand["official_telegram"]}


def load(path: str | Path | None = None) -> Config:
    path = Path(path or os.environ.get("SHIELD_CONFIG", ROOT / "config.yaml"))
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return Config(brand=raw["brand"], scoring=raw["scoring"], network=raw["network"],
                  analyze=raw.get("analyze", {}), llm=raw.get("llm", {"provider": "none"}), takedown=raw.get("takedown") or {})
