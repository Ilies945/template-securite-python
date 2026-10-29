"""Orchestration de l'analyse d'un échantillon."""
from __future__ import annotations

import logging
import re
from pathlib import Path

from . import scoring
from .binary import parse_binary
from .deobfuscate import collect_texts
from .injection import detect_injection
from .iocs import extract_iocs_from_texts, find_flag
from .llm import LLMClient, llm_triage
from .metadata import get_file_metadata
from .scanner import yara_scan_detailed

log = logging.getLogger(__name__)
INJECTION_RULE = "Custom_LLM_Manipulation_Text"


def _api_names_in_strings(strings: list[str]) -> list[str]:
    """API suspectes citées en clair (fichiers sans table d'imports exploitable)."""
    known = {n for _t, _c, apis in scoring.API_CATEGORIES.values() for n in apis}
    pattern = re.compile(r"\b(" + "|".join(sorted(map(re.escape, known), key=len, reverse=True)) + r")\b")
    return sorted({m for s in strings for m in pattern.findall(s)})


def deterministic_summary(result: dict, details: dict) -> str:
    """Synthèse lisible produite sans LLM (repli)."""
    parts = []
    score, fam = result["score"], result["family_guess"]
    if fam == "benign":
        parts.append("Aucun comportement malveillant caractérisé n'a été identifié.")
    else:
        parts.append(f"Échantillon jugé suspect (score {score}/10), famille probable : {fam}.")
    if result["yara_matches"]:
        parts.append("Règles YARA déclenchées : " + ", ".join(result["yara_matches"][:6]) + ".")
    iocs = result["iocs"]
    seen = [f"{len(iocs[k])} {k}" for k in ("urls", "domains", "ips", "mutex", "registry") if iocs[k]]
    if seen:
        parts.append("Indicateurs extraits : " + ", ".join(seen) + ".")
    if details["capabilities"]:
        parts.append("Capacités : " + "; ".join(details["capabilities"][:4]) + ".")
    if details["injection"]:
        parts.append("Le fichier contient une tentative d'injection de prompt visant l'analyse automatisée ; elle a été ignorée et traitée comme un indicateur malveillant.")
    return " ".join(parts)


def analyze_file(path: str | Path, rules, client: LLMClient | None = None) -> tuple[dict, dict]:
    """Analyse un fichier et renvoie (résultat conforme au contrat, détails pour le PDF)."""
    path = Path(path)
    data = path.read_bytes()
    meta = get_file_metadata(data)

    texts = collect_texts(data)
    all_iocs = extract_iocs_from_texts(texts)
    flag = find_flag(data, texts)
    binary = parse_binary(path)
    yara_meta = yara_scan_detailed(data, rules)

    injection = detect_injection(texts.plain)
    injected = bool(injection) or INJECTION_RULE in yara_meta
    if INJECTION_RULE in yara_meta and not injection:
        injection = ["(motif d'injection repéré par la règle YARA " + INJECTION_RULE + ")"]

    api_hits = _api_names_in_strings(texts.plain)
    import_cats = scoring.categorize_imports(sorted({*binary["imports"], *api_hits}))
    base = scoring.base_score(yara_meta, all_iocs, import_cats, meta["entropy"], injection)
    mitre = scoring.infer_mitre(yara_meta, import_cats, all_iocs)
    caps = scoring.capabilities(import_cats, yara_meta, all_iocs)

    summary = {
        **meta,
        "iocs": all_iocs,
        "imports": binary["imports"] or api_hits,
        "sections": binary["sections"],
        "yara_matches": sorted(yara_meta),
        "base_score": base,
        "injection": injection,
    }
    verdict = llm_triage(summary, client) if client is not None else None

    llm_score = verdict["score"] if verdict else None
    score = scoring.final_score(base, llm_score, injected)
    family = scoring.guess_family(yara_meta, import_cats, all_iocs, score)
    if verdict and verdict["family"] and not injected:
        # Le LLM ne peut pas déclarer « benign » un fichier objectivement suspect.
        if verdict["family"] != "benign" or score <= 2:
            family = verdict["family"]
    if verdict and not injected:
        mitre = sorted(set(mitre) | set(verdict["mitre_attack"]))
        caps = sorted(set(caps) | set(verdict["capabilities"]))

    result = {
        **meta,
        "iocs": {k: all_iocs[k] for k in ("domains", "ips", "urls", "mutex", "registry")},
        "imports": binary["imports"],
        "yara_matches": sorted(yara_meta),
        "family_guess": family,
        "mitre_attack": mitre,
        "score": score,
        "flag": flag,
    }
    details = {
        "paths": all_iocs["paths"],
        "sections": binary["sections"],
        "exports": binary["exports"],
        "capabilities": caps,
        "injection": injection,
        "base_score": base,
        "llm_used": verdict is not None,
    }
    summary_text = verdict["summary"] if verdict and verdict["summary"] else ""
    if not summary_text:
        summary_text = deterministic_summary(result, {**details, "capabilities": caps})
    elif injected:
        summary_text += " [Alerte : tentative d'injection de prompt détectée dans le fichier et ignorée.]"
    result["llm_summary"] = summary_text
    return result, details
