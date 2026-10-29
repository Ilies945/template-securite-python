"""Analyse structurelle des exécutables PE / ELF avec lief."""
from __future__ import annotations

from pathlib import Path

EMPTY: dict = {"format": None, "imports": [], "exports": [], "sections": []}


def _sorted_unique(values) -> list[str]:
    return sorted({str(v) for v in values if v})


def _pe_info(binary) -> dict:
    imports: list[str] = []
    for lib in binary.imports:
        imports.extend(entry.name for entry in lib.entries if entry.name)
    exports = [e.name for e in binary.exported_functions if getattr(e, "name", "")]
    sections = [
        {
            "name": s.name,
            "size": int(s.size),
            "virtual_size": int(s.virtual_size),
            "entropy": round(float(s.entropy), 4),
        }
        for s in binary.sections
    ]
    return {"format": "PE", "imports": imports, "exports": exports, "sections": sections}


def _elf_info(binary) -> dict:
    imports = [sym.name for sym in binary.imported_symbols if sym.name]
    exports = [sym.name for sym in binary.exported_symbols if sym.name]
    sections = [
        {
            "name": s.name,
            "size": int(s.size),
            "virtual_size": int(s.size),
            "entropy": round(float(s.entropy), 4),
        }
        for s in binary.sections
    ]
    return {"format": "ELF", "imports": imports, "exports": exports, "sections": sections}


def parse_binary(path: str | Path) -> dict:
    """Imports, exports et sections d'un PE ou ELF ; structure vide pour tout autre fichier."""
    result = {k: list(v) if isinstance(v, list) else v for k, v in EMPTY.items()}
    try:
        import lief

        lief.logging.disable()
        binary = lief.parse(str(path))
        if binary is None:
            return result
        if isinstance(binary, lief.PE.Binary):
            info = _pe_info(binary)
        elif isinstance(binary, lief.ELF.Binary):
            info = _elf_info(binary)
        else:
            return result
    except Exception:  # fichier corrompu / tronqué : on ne plante jamais le triage
        return result
    info["imports"] = _sorted_unique(info["imports"])
    info["exports"] = _sorted_unique(info["exports"])
    return info
