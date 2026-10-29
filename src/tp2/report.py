"""Génération des rapports : JSON machine-lisible (contrat) + PDF lisible."""
from __future__ import annotations

import json
import logging
from pathlib import Path

log = logging.getLogger(__name__)

CONTRACT_KEYS = (
    "sha256", "md5", "size", "entropy", "file_type", "iocs", "imports", "yara_matches",
    "family_guess", "mitre_attack", "llm_summary", "score", "flag",
)
IOC_KEYS = ("domains", "ips", "urls", "mutex", "registry")


def contract_view(result: dict) -> dict:
    """Ne conserve que les champs du format de sortie, dans l'ordre attendu."""
    out = {k: result.get(k) for k in CONTRACT_KEYS}
    out["iocs"] = {k: list((result.get("iocs") or {}).get(k, [])) for k in IOC_KEYS}
    for key in ("imports", "yara_matches", "mitre_attack"):
        out[key] = list(out[key] or [])
    out["flag"] = out["flag"] or ""
    return out


def write_json(result: dict, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{result['sha256']}.json"
    path.write_text(json.dumps(contract_view(result), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def _latin(text: object) -> str:
    return str(text).encode("latin-1", "replace").decode("latin-1")


def _pdf_line(pdf, text: str, size: int = 10, style: str = "", h: float = 5.5) -> None:
    from fpdf.enums import WrapMode

    pdf.set_font("Helvetica", style, size)
    pdf.multi_cell(0, h, _latin(text), wrapmode=WrapMode.CHAR, new_x="LMARGIN", new_y="NEXT")


def _pdf_section(pdf, title: str) -> None:
    pdf.ln(2)
    pdf.set_fill_color(230, 235, 245)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, _latin(title), fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)


def _pdf_bullets(pdf, items: list[str], limit: int = 40) -> None:
    if not items:
        _pdf_line(pdf, "(aucun)", style="I")
        return
    for item in items[:limit]:
        _pdf_line(pdf, f"  - {item}", size=9, h=4.8)
    if len(items) > limit:
        _pdf_line(pdf, f"  ... et {len(items) - limit} autres", size=9, style="I")


def write_pdf(result: dict, details: dict, path: Path) -> Path:
    from fpdf import FPDF

    pdf = FPDF()
    pdf.set_auto_page_break(True, margin=15)
    pdf.add_page()

    score = int(result.get("score") or 0)
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Rapport de triage malware", new_x="LMARGIN", new_y="NEXT")
    color = (200, 40, 40) if score >= 7 else (220, 140, 20) if score >= 4 else (40, 150, 70)
    pdf.set_text_color(*color)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, _latin(f"Score {score}/10 - famille probable : {result.get('family_guess')}"),
             new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)

    _pdf_section(pdf, "Fichier")
    for label, key in (("SHA-256", "sha256"), ("MD5", "md5"), ("Taille (octets)", "size"),
                       ("Entropie", "entropy"), ("Type", "file_type")):
        _pdf_line(pdf, f"{label} : {result.get(key)}", size=9)
    if result.get("flag"):
        _pdf_line(pdf, f"Flag : {result['flag']}", size=10, style="B")

    _pdf_section(pdf, "Synthèse")
    _pdf_line(pdf, result.get("llm_summary") or "(aucune)")
    if details.get("injection"):
        pdf.set_text_color(200, 40, 40)
        _pdf_line(pdf, "ALERTE : tentative d'injection de prompt détectée dans le fichier (ignorée par le pipeline).", style="B")
        pdf.set_text_color(0, 0, 0)
        _pdf_bullets(pdf, details["injection"], 5)
    _pdf_line(pdf, f"Score objectif (YARA/IOC/imports) : {details.get('base_score')} - "
         f"analyse LLM utilisée : {'oui' if details.get('llm_used') else 'non (repli déterministe)'}", size=9)

    _pdf_section(pdf, "Règles YARA")
    _pdf_bullets(pdf, result.get("yara_matches", []))
    _pdf_section(pdf, "MITRE ATT&CK")
    _pdf_bullets(pdf, result.get("mitre_attack", []))
    _pdf_section(pdf, "Capacités")
    _pdf_bullets(pdf, details.get("capabilities", []))
    for key in IOC_KEYS:
        _pdf_section(pdf, f"IOC - {key}")
        _pdf_bullets(pdf, (result.get("iocs") or {}).get(key, []))
    _pdf_section(pdf, "IOC - chemins")
    _pdf_bullets(pdf, details.get("paths", []), 25)
    _pdf_section(pdf, "Imports")
    _pdf_bullets(pdf, result.get("imports", []), 60)
    if details.get("sections"):
        _pdf_section(pdf, "Sections")
        _pdf_bullets(pdf, [f"{s['name']} - taille {s['size']} - entropie {s['entropy']}" for s in details["sections"]], 20)

    path.parent.mkdir(parents=True, exist_ok=True)
    pdf.output(str(path))
    return path


def generate_report(result: dict, out_dir: str | Path, details: dict | None = None) -> tuple[Path, Path | None]:
    """Écrit `<sha256>.json` (contrat) dans out_dir et `reports/<sha256>.pdf`.

    Le PDF est placé dans un sous-dossier pour que `--out` ne contienne, à sa racine,
    qu'un JSON par échantillon. Une erreur de PDF ne doit jamais perdre le JSON.
    """
    out = Path(out_dir)
    json_path = write_json(result, out)
    pdf_path: Path | None = None
    try:
        pdf_path = write_pdf(contract_view(result), details or {}, out / "reports" / f"{result['sha256']}.pdf")
    except Exception as exc:
        log.warning("PDF non généré pour %s : %s", result.get("sha256"), exc)
    return json_path, pdf_path
