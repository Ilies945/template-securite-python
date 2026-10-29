"""Scan YARA : règles fournies (--rules) + règles personnelles (rules/)."""
from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger(__name__)
RULE_SUFFIXES = {".yar", ".yara"}


def find_rule_files(*rule_dirs: str | Path) -> list[Path]:
    files: dict[str, Path] = {}
    for d in rule_dirs:
        if not d:
            continue
        base = Path(d)
        if base.is_file() and base.suffix.lower() in RULE_SUFFIXES:
            files[str(base.resolve())] = base
        elif base.is_dir():
            for f in base.rglob("*"):
                if f.is_file() and f.suffix.lower() in RULE_SUFFIXES:
                    files[str(f.resolve())] = f
    return [files[k] for k in sorted(files)]


def compile_rules(*rule_dirs: str | Path):
    """Compile chaque fichier séparément : une règle invalide n'invalide pas les autres."""
    import yara

    sources: dict[str, str] = {}
    for i, f in enumerate(find_rule_files(*rule_dirs)):
        try:
            yara.compile(filepath=str(f))  # validation isolée
        except yara.Error as exc:
            log.warning("Règle ignorée (%s) : %s", f, exc)
            continue
        sources[f"r{i}"] = str(f)
    if not sources:
        return None
    # Deux fichiers peuvent définir la même règle : on les compile alors un par un.
    try:
        return [yara.compile(filepaths=sources)]
    except yara.Error:
        compiled = []
        for ns, path in sources.items():
            try:
                compiled.append(yara.compile(filepath=path))
            except yara.Error:
                continue
        return compiled or None


def yara_scan_detailed(data: bytes, rules) -> dict[str, dict]:
    """{nom_de_règle: métadonnées} pour chaque règle qui matche `data`.

    `rules` : objet compilé, liste d'objets compilés, ou dossier(s) de règles.
    """
    if rules is None:
        return {}
    if isinstance(rules, (str, Path)):
        rules = compile_rules(rules)
        if rules is None:
            return {}
    if not isinstance(rules, (list, tuple)):
        rules = [rules]
    matches: dict[str, dict] = {}
    for compiled in rules:
        try:
            for m in compiled.match(data=data, timeout=30):
                matches.setdefault(m.rule, dict(m.meta))
        except Exception as exc:  # timeout ou erreur moteur
            log.warning("Scan YARA interrompu : %s", exc)
    return matches


def yara_scan(data: bytes, rules) -> list[str]:
    """Noms des règles qui matchent `data` (triés, sans doublon)."""
    return sorted(yara_scan_detailed(data, rules))
