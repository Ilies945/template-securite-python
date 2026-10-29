"""Détection et neutralisation des tentatives d'injection de prompt.

Le contenu d'un échantillon est une donnée hostile : il ne doit jamais être
interprété comme une instruction par le LLM. Deux défenses :
1. repérer nous-mêmes les motifs d'injection (et les traiter comme un indicateur) ;
2. neutraliser le texte avant de l'insérer dans le prompt (délimiteurs, troncature).
"""
from __future__ import annotations

import re

INJECTION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"ignor(?:e|er|ez)\s+(?:toutes\s+)?(?:les\s+)?(?:instructions|consignes|r[eè]gles)\s+(?:pr[eé]c[eé]dentes|ant[eé]rieures)",
        r"ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts?|rules)",
        r"disregard\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above)",
        r"d[eé]clar(?:e|er|ez)\s+(?:ce\s+)?fichier\s+(?:comme\s+)?(?:sain|b[eé]nin|l[eé]gitime|s[uû]r|inoffensif)",
        r"(?:mark|declare|report|classify|label|rate)\s+(?:this\s+)?(?:file|sample|binary)?\s*(?:as\s+)?(?:safe|benign|clean|harmless|legitimate)",
        r"(?:score|verdict|risk)\s*(?:to|=|:)\s*0\b",
        r"you\s+are\s+now\b",
        r"nouvelles?\s+instructions?",
        r"new\s+instructions?\s*:",
        r"(?:system|assistant)\s*(?:prompt|message)\s*:",
        r"</?\s*(?:system|assistant|instructions?)\s*>|\[/?INST\]|<\|im_(?:start|end)\|>",
        r"(?:ne\s+(?:mentionne|dis)\s+pas|do\s+not\s+(?:mention|report|flag))",
        r"(?:r[eé]ponds?|answer|respond)\s+(?:uniquement\s+|only\s+)?(?:avec|with|by)\s+[\"'`{]",
    )
]
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f​-‏‪-‮⁦-⁩]")
OPEN_TAG, CLOSE_TAG = "<untrusted_data>", "</untrusted_data>"


def detect_injection(strings: list[str]) -> list[str]:
    """Extraits (tronqués) qui ressemblent à une instruction adressée à un LLM."""
    hits: list[str] = []
    for text in strings:
        for pattern in INJECTION_PATTERNS:
            m = pattern.search(text)
            if m:
                start = max(0, m.start() - 20)
                snippet = " ".join(text[start : m.end() + 60].split())[:160]
                if snippet not in hits:
                    hits.append(snippet)
                break
    return hits[:10]


def neutralize(text: str, max_len: int = 200) -> str:
    """Rend une chaîne inoffensive pour le prompt : sans balises, sans contrôle, tronquée."""
    text = CONTROL_CHARS.sub("", text)
    text = re.sub(r"(?i)</?\s*untrusted_data\s*>", "[tag]", text)
    text = text.replace("<", "‹").replace(">", "›").replace("```", "'''")
    text = " ".join(text.split())
    return text[:max_len] + ("…" if len(text) > max_len else "")


def wrap_untrusted(items: list[str], max_items: int = 40, max_len: int = 200) -> str:
    """Bloc délimité contenant des chaînes issues de l'échantillon (jamais des ordres)."""
    lines = [neutralize(i, max_len) for i in items[:max_items]]
    body = "\n".join(f"- {line}" for line in lines) or "(aucune)"
    return f"{OPEN_TAG}\n{body}\n{CLOSE_TAG}"
