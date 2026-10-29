"""Point d'entrée : `poetry run tp2 --samples DOSSIER --rules DOSSIER --out DOSSIER`."""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import config

from .llm import LLMClient
from .pipeline import analyze_file
from .report import generate_report
from .scanner import compile_rules

log = logging.getLogger("tp2")
BUNDLED_RULES = config.ROOT_DIR / "rules"


def list_samples(samples: Path) -> list[Path]:
    if samples.is_file():
        return [samples]
    return sorted(p for p in samples.rglob("*") if p.is_file() and not p.name.startswith("."))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tp2", description="Triage automatisé de malware")
    p.add_argument("--samples", required=True, type=Path, help="dossier des échantillons")
    p.add_argument("--rules", required=True, type=Path, help="dossier des règles YARA")
    p.add_argument("--out", required=True, type=Path, help="dossier de sortie (un JSON par échantillon)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def run(samples: Path, rules_dir: Path, out: Path) -> int:
    """Analyse chaque échantillon ; renvoie le nombre de rapports écrits."""
    out.mkdir(parents=True, exist_ok=True)
    rules = compile_rules(rules_dir, BUNDLED_RULES)
    if rules is None:
        log.warning("Aucune règle YARA exploitable (%s, %s)", rules_dir, BUNDLED_RULES)
    client = LLMClient()
    written = 0
    for path in list_samples(samples):
        try:
            result, details = analyze_file(path, rules, client)
            json_path, _pdf = generate_report(result, out, details)
            written += 1
            log.info("%s -> %s (score %s, %s)", path.name, json_path.name, result["score"], result["family_guess"])
        except Exception:  # un échantillon illisible ne doit pas arrêter le lot
            log.exception("Échec d'analyse pour %s", path)
    return written


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
        stream=sys.stderr,
    )
    if not args.samples.exists():
        log.error("Dossier d'échantillons introuvable : %s", args.samples)
        return 2
    count = run(args.samples, args.rules, args.out)
    log.info("%d rapport(s) écrit(s) dans %s", count, args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
