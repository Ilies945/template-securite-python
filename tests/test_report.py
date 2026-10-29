import json

from tp2 import report as r

RESULT = {
    "sha256": "a" * 64, "md5": "b" * 32, "size": 10, "entropy": 1.5, "file_type": "data",
    "iocs": {"domains": ["c2.example.test"], "ips": [], "urls": [], "mutex": [], "registry": [], "paths": ["C:\\x"]},
    "imports": ["connect"], "yara_matches": ["R"], "family_guess": "dropper", "mitre_attack": ["T1071"],
    "llm_summary": "Résumé accentué – avec des caractères hors latin-1 : ✓ 日本", "score": 8, "flag": None,
    "extra_internal_field": "ne doit pas fuiter",
}
DETAILS = {"injection": ["ignore les instructions"], "base_score": 7, "llm_used": False,
           "capabilities": ["réseau"], "paths": ["C:\\x"], "sections": [{"name": ".text", "size": 1, "entropy": 1.0}]}


def test_contract_view_has_exact_keys_and_order():
    view = r.contract_view(RESULT)
    assert tuple(view) == r.CONTRACT_KEYS
    assert tuple(view["iocs"]) == r.IOC_KEYS
    assert view["flag"] == ""
    assert "extra_internal_field" not in view


def test_write_json_named_after_sha256(tmp_path):
    path = r.write_json(RESULT, tmp_path / "out")
    assert path.name == "a" * 64 + ".json"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["score"] == 8 and data["iocs"]["domains"] == ["c2.example.test"]
    assert "Résumé accentué" in path.read_text(encoding="utf-8")


def test_latin_replaces_unencodable_chars():
    assert r._latin("é✓日") == "é??"


def test_write_pdf_creates_readable_pdf(tmp_path):
    path = r.write_pdf(r.contract_view(RESULT), DETAILS, tmp_path / "sub" / "x.pdf")
    assert path.read_bytes().startswith(b"%PDF")
    assert path.stat().st_size > 1000


def test_write_pdf_survives_huge_unbreakable_strings(tmp_path):
    big = {**RESULT, "iocs": {**RESULT["iocs"], "urls": ["http://x.test/" + "A" * 3000]}, "imports": ["I" * 500] * 100}
    assert r.write_pdf(r.contract_view(big), {}, tmp_path / "big.pdf").exists()


def test_generate_report_writes_json_and_pdf(tmp_path):
    json_path, pdf_path = r.generate_report(RESULT, tmp_path, DETAILS)
    assert json_path.parent == tmp_path and json_path.exists()
    assert pdf_path == tmp_path / "reports" / ("a" * 64 + ".pdf") and pdf_path.exists()
    assert [p.name for p in tmp_path.glob("*")] == [json_path.name, "reports"]


def test_generate_report_keeps_json_when_pdf_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(r, "write_pdf", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("pdf cassé")))
    json_path, pdf_path = r.generate_report(RESULT, tmp_path, DETAILS)
    assert json_path.exists() and pdf_path is None
