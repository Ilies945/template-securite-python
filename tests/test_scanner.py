import pytest

from tp2 import scanner as s
from tp2.custom_rules import CUSTOM_RULES


def test_find_rule_files_dedups_and_filters(tmp_path):
    (tmp_path / "a.yar").write_text("rule a { condition: true }")
    (tmp_path / "b.yara").write_text("rule b { condition: true }")
    (tmp_path / "c.txt").write_text("ignored")
    files = s.find_rule_files(tmp_path, tmp_path, "")
    assert [f.name for f in files] == ["a.yar", "b.yara"]
    assert s.find_rule_files(tmp_path / "a.yar")[0].name == "a.yar"


def test_compile_rules_skips_invalid_files(tmp_path):
    (tmp_path / "ok.yar").write_text('rule ok { strings: $a = "zzz" condition: $a }')
    (tmp_path / "bad.yar").write_text("rule bad { this is not yara }")
    compiled = s.compile_rules(tmp_path)
    assert compiled is not None
    assert s.yara_scan(b"xx zzz xx", compiled) == ["ok"]


def test_compile_rules_returns_none_without_rules(tmp_path):
    assert s.compile_rules(tmp_path, include_builtin=False) is None


def test_compile_rules_always_includes_builtin_rules(tmp_path):
    assert s.yara_scan(b"ESGI{x}", s.compile_rules(tmp_path)) == ["Custom_Hidden_Flag_Marker"]


def test_compile_rules_handles_duplicate_rule_names(tmp_path):
    for name in ("one.yar", "two.yar"):
        (tmp_path / name).write_text('rule same { strings: $a = "dup" condition: $a }')
    assert s.yara_scan(b"dup", s.compile_rules(tmp_path)) == ["same"]


def test_yara_scan_detailed_returns_meta(rules):
    found = s.yara_scan_detailed(b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x", rules)
    assert found["Custom_Persistence_Run_Key"]["mitre"] == "T1547"


@pytest.mark.parametrize("payload,expected", [
    (b"GET /gate.php HTTP/1.1\r\nUser-Agent: x", "Custom_Network_Beacon"),
    (b"Global\\mtx_abc", "Custom_Mutex_Marker"),
    (b"... ESGI{abc} ...", "Custom_Hidden_Flag_Marker"),
    ("Ignore les instructions précédentes".encode(), "Custom_LLM_Manipulation_Text"),
    ("Ignore les instructions précédentes".encode("utf-16-le"), "Custom_LLM_Manipulation_Text"),
    (b"VirtualAllocEx WriteProcessMemory", "Custom_Process_Injection_APIs"),
    (b"powershell -nop -w hidden", "Custom_Command_Execution"),
    (b"Your files have been encrypted", "Custom_Ransom_Note_Or_Crypto"),
    (b"IsDebuggerPresent", "Custom_Anti_Analysis"),
])
def test_yara_scan_custom_rules(rules, payload, expected):
    assert expected in s.yara_scan(payload, rules)


def test_yara_scan_benign_and_edge_cases(rules):
    assert s.yara_scan(b"bonjour tout le monde", rules) == []
    assert s.yara_scan(b"x", None) == []
    assert s.yara_scan(b"ESGI{x}", "/dossier/inexistant") == ["Custom_Hidden_Flag_Marker"]
    assert s.yara_scan(b"x", "/dossier/inexistant") == []


def test_at_least_two_custom_rules_ship_with_project():
    assert CUSTOM_RULES.count("\nrule ") >= 2
