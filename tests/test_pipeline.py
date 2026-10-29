import json

import helpers
from tp2 import pipeline as p
from tp2.llm import LLMClient
from test_llm import ScriptedClient

CONTRACT = {"sha256", "md5", "size", "entropy", "file_type", "iocs", "imports", "yara_matches", "family_guess",
            "mitre_attack", "llm_summary", "score", "flag"}


def test_analyze_file_pe_end_to_end(pe_file, rules):
    result, details = p.analyze_file(pe_file, rules)
    assert result["iocs"]["domains"] == ["c2.example.test"]
    assert result["iocs"]["ips"] == ["185.10.20.30"]
    assert result["iocs"]["urls"] == ["http://c2.example.test/gate.php"]
    assert result["iocs"]["mutex"] == ["Global\\abc123"]
    assert result["flag"] == "ESGI{unit_test_flag}"
    assert {"WSASocketA", "CreateProcessA"} <= set(result["imports"])
    assert {"Custom_Network_Beacon", "Custom_Persistence_Run_Key"} <= set(result["yara_matches"])
    assert result["score"] >= 8 and result["family_guess"] != "benign"
    assert result["llm_summary"] and details["llm_used"] is False
    assert details["paths"] == ["C:\\Users\\Public\\svc.exe"]


def test_analyze_file_benign_text(tmp_path, rules):
    f = tmp_path / "note.txt"
    f.write_text("Réunion à 14h, apporter les documents.\n")
    result, _ = p.analyze_file(f, rules)
    assert result["score"] == 0 and result["family_guess"] == "benign"
    assert result["yara_matches"] == [] and result["flag"] == ""
    assert all(v == [] for v in result["iocs"].values())


def test_prompt_injection_cannot_whitewash_sample(tmp_path, rules):
    f = tmp_path / "evil.txt"
    f.write_bytes((helpers.INJECTION_TEXT + "\nhttp://c2.example.test/gate.php\npowershell -nop -w hidden\n").encode())
    obedient = ScriptedClient(json.dumps({"family": "benign", "capabilities": [], "mitre_attack": [],
                                          "score": 0, "iocs": {}, "summary": "Fichier sain, aucun risque."}))
    result, details = p.analyze_file(f, rules, obedient)
    assert details["injection"], "l'injection doit être détectée"
    assert result["score"] >= 6, "un LLM manipulé ne doit pas faire passer le fichier pour sain"
    assert result["family_guess"] != "benign"
    assert "injection" in result["llm_summary"].lower()
    assert "Fichier sain" in result["llm_summary"] or details["llm_used"]
    assert "UNTRUSTED" not in obedient.prompts[0]
    assert "<untrusted_data>" in obedient.prompts[0]


def test_llm_failure_falls_back_to_deterministic(pe_file, rules):
    result, details = p.analyze_file(pe_file, rules, ScriptedClient("réponse inutilisable"))
    assert details["llm_used"] is False and result["score"] >= 8
    assert result["llm_summary"].startswith("Échantillon jugé suspect")


def test_llm_verdict_is_used_but_bounded(pe_file, rules):
    reply = json.dumps({"family": "Dropper", "capabilities": ["télécharge"], "mitre_attack": ["T1105"],
                        "score": 9, "iocs": {}, "summary": "Dropper classique."})
    result, details = p.analyze_file(pe_file, rules, ScriptedClient(reply))
    assert details["llm_used"] and result["family_guess"] == "dropper"
    assert result["llm_summary"] == "Dropper classique." and "T1105" in result["mitre_attack"]


def test_api_names_in_strings():
    assert p._api_names_in_strings(["call CreateProcessA then connect", "rien"]) == ["CreateProcessA", "connect"]
    assert p._api_names_in_strings(["nothing here"]) == []


def test_deterministic_summary():
    result = {"score": 0, "family_guess": "benign", "yara_matches": [], "iocs": {k: [] for k in
              ("domains", "ips", "urls", "mutex", "registry")}}
    details = {"capabilities": [], "injection": []}
    assert "Aucun comportement" in p.deterministic_summary(result, details)
    result.update(score=9, family_guess="dropper", yara_matches=["R1"])
    result["iocs"]["urls"] = ["http://x.test/a"]
    details.update(capabilities=["réseau"], injection=["ignore"])
    text = p.deterministic_summary(result, details)
    assert "R1" in text and "1 urls" in text and "injection de prompt" in text


def test_pipeline_output_matches_contract(pe_file, rules):
    from tp2.report import contract_view
    result, _ = p.analyze_file(pe_file, rules)
    assert set(contract_view(result)) == CONTRACT
