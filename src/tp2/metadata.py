"""Métadonnées de fichier : empreintes, taille, type, entropie."""
from __future__ import annotations

import hashlib
import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """Entropie de Shannon en bits/octet (0.0 à 8.0)."""
    if not data:
        return 0.0
    total = len(data)
    counts = Counter(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def detect_file_type(data: bytes) -> str:
    """Type du fichier via python-magic, avec repli minimal si libmagic manque."""
    try:
        import magic

        return str(magic.from_buffer(data))
    except Exception:  # libmagic absente ou erreur d'analyse
        if data[:2] == b"MZ":
            return "PE executable"
        if data[:4] == b"\x7fELF":
            return "ELF executable"
        return "data"


def get_file_metadata(data: bytes) -> dict:
    """SHA-256, MD5, taille, type (python-magic) et entropie de Shannon."""
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),  # noqa: S324 - empreinte, pas de crypto
        "size": len(data),
        "file_type": detect_file_type(data),
        "entropy": round(shannon_entropy(data), 4),
    }
