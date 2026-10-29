import sys
from types import SimpleNamespace

import pytest

from tp2 import binary as b


def test_parse_binary_pe(pe_file):
    info = b.parse_binary(pe_file)
    assert info["format"] == "PE"
    assert {"WSASocketA", "connect", "CreateProcessA", "VirtualAllocEx", "WriteProcessMemory"} <= set(info["imports"])
    assert [s["name"] for s in info["sections"]] == [".text", ".rdata", ".idata"]
    assert info["imports"] == sorted(info["imports"])


def test_parse_binary_non_executable_returns_empty(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("juste du texte")
    assert b.parse_binary(path) == {"format": None, "imports": [], "exports": [], "sections": []}


def test_parse_binary_corrupted_pe_does_not_crash(tmp_path, pe_bytes):
    path = tmp_path / "broken.exe"
    path.write_bytes(pe_bytes[:300])
    info = b.parse_binary(path)
    assert set(info) == {"format", "imports", "exports", "sections"}


def test_parse_binary_missing_file_does_not_crash(tmp_path):
    assert b.parse_binary(tmp_path / "absent.bin")["imports"] == []


@pytest.mark.skipif(not open(sys.executable, "rb").read(4) == b"\x7fELF", reason="interpréteur non ELF")
def test_parse_binary_real_elf():
    info = b.parse_binary(sys.executable)
    assert info["format"] == "ELF"
    assert info["sections"]


def test_sorted_unique():
    assert b._sorted_unique(["b", "a", "b", "", None]) == ["a", "b"]


def test_pe_info_reads_imports_exports_sections():
    entry = SimpleNamespace(name="connect")
    binary = SimpleNamespace(
        imports=[SimpleNamespace(entries=[entry, SimpleNamespace(name="")])],
        exported_functions=[SimpleNamespace(name="Run")],
        sections=[SimpleNamespace(name=".text", size=10, virtual_size=16, entropy=1.23456789)],
    )
    info = b._pe_info(binary)
    assert info["format"] == "PE"
    assert info["imports"] == ["connect"]
    assert info["exports"] == ["Run"]
    assert info["sections"][0] == {"name": ".text", "size": 10, "virtual_size": 16, "entropy": 1.2346}


def test_elf_info_reads_symbols_and_sections():
    binary = SimpleNamespace(
        imported_symbols=[SimpleNamespace(name="execve"), SimpleNamespace(name="")],
        exported_symbols=[SimpleNamespace(name="main")],
        sections=[SimpleNamespace(name=".text", size=32, entropy=2.0)],
    )
    info = b._elf_info(binary)
    assert info["format"] == "ELF"
    assert info["imports"] == ["execve"]
    assert info["exports"] == ["main"]
    assert info["sections"][0]["size"] == 32
