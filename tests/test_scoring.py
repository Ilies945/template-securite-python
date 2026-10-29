from tp2 import scoring as sc

EMPTY_IOCS = {"domains": [], "ips": [], "urls": [], "mutex": [], "registry": [], "paths": []}
C2_IOCS = {**EMPTY_IOCS, "urls": ["http://c2.example.test/g"], "domains": ["c2.example.test"],
           "registry": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svc"]}


def test_categorize_imports():
    cats = sc.categorize_imports(["WSASocketA", "CreateProcessA", "Unknown", "virtualallocex"])
    assert cats["network"] == ["WSASocketA"]
    assert cats["execution"] == ["CreateProcessA"]
    assert cats["injection"] == ["virtualallocex"]
    assert sc.categorize_imports([]) == {}


def test_infer_mitre_from_all_sources():
    meta = {"Rule_A": {"mitre": "T1547, T1059.001"}, "Downloader_Rule": {}}
    cats = sc.categorize_imports(["VirtualAllocEx"])
    techniques = sc.infer_mitre(meta, cats, C2_IOCS)
    assert {"T1547", "T1059.001", "T1105", "T1055", "T1071"} <= set(techniques)
    assert techniques == sorted(techniques)
    assert sc.infer_mitre({}, {}, EMPTY_IOCS) == []


def test_base_score_benign_is_zero():
    assert sc.base_score({}, EMPTY_IOCS, {}, 3.0, []) == 0


def test_base_score_grows_with_evidence():
    meta = {"Custom_Network_Beacon": {}, "Custom_Persistence_Run_Key": {}}
    cats = sc.categorize_imports(["VirtualAllocEx", "WriteProcessMemory", "CreateProcessA"])
    assert sc.base_score(meta, C2_IOCS, cats, 7.5, []) >= 9


def test_base_score_injection_is_a_malicious_signal():
    plain = sc.base_score({}, EMPTY_IOCS, {}, 3.0, [])
    assert sc.base_score({}, EMPTY_IOCS, {}, 3.0, ["ignore les instructions"]) > plain


def test_base_score_flag_marker_alone_is_not_malicious():
    assert sc.base_score({"Custom_Hidden_Flag_Marker": {}}, EMPTY_IOCS, {}, 3.0, []) == 0


def test_final_score_llm_cannot_whitewash():
    assert sc.final_score(8, 0, injection=True) == 8
    assert sc.final_score(8, 0, injection=False) == 6
    assert sc.final_score(2, 10, injection=False) == 5
    assert sc.final_score(4, None, injection=False) == 4
    assert 0 <= sc.final_score(0, 10, injection=False) <= 10


def test_normalize_family():
    assert sc.normalize_family("Dropper") == "dropper"
    assert sc.normalize_family("Trojan Downloader") == "dropper"
    assert sc.normalize_family("clean") == "benign"
    assert sc.normalize_family("unicorn") is None
    assert sc.normalize_family(None) is None


def test_guess_family():
    net_exec = sc.categorize_imports(["WSASocketA", "CreateProcessA"])
    assert sc.guess_family({}, {}, EMPTY_IOCS, 0) == "benign"
    assert sc.guess_family({"Evil_Ransomware": {}}, {}, EMPTY_IOCS, 8) == "ransomware"
    assert sc.guess_family({"Suspicious_Downloader": {}}, {}, EMPTY_IOCS, 6) == "dropper"
    assert sc.guess_family({"Custom_X": {}}, sc.categorize_imports(["URLDownloadToFileA"]), EMPTY_IOCS, 6) == "dropper"
    assert sc.guess_family({"Custom_Persistence_Run_Key": {}}, net_exec, C2_IOCS, 7) in {"dropper", "backdoor"}
    assert sc.guess_family({"Custom_X": {}}, sc.categorize_imports(["SetWindowsHookExA"]), EMPTY_IOCS, 6) == "stealer"
    assert sc.guess_family({"Custom_X": {}}, sc.categorize_imports(["VirtualAllocEx"]), EMPTY_IOCS, 6) == "loader"


def test_capabilities():
    caps = sc.capabilities(sc.categorize_imports(["WSASocketA"]), {"R": {"description": "Beacon HTTP"}}, C2_IOCS)
    assert "communication réseau (C2)" in caps
    assert "persistance" in caps
    assert "Beacon HTTP" in caps
    assert caps == sorted(caps)
