import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import helpers  # noqa: E402


@pytest.fixture(autouse=True)
def _offline_llm(monkeypatch):
    """Les tests ne dépendent jamais du réseau : LLM désactivé par défaut."""
    monkeypatch.setenv("TP2_LLM_BACKEND", "none")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)


@pytest.fixture
def pe_bytes():
    return helpers.build_pe(
        {"WS2_32.dll": ["WSASocketA", "connect"],
         "KERNEL32.dll": ["CreateProcessA", "VirtualAllocEx", "WriteProcessMemory"]},
        helpers.C2_STRINGS,
    )


@pytest.fixture
def pe_file(tmp_path, pe_bytes):
    path = tmp_path / "dropper.exe"
    path.write_bytes(pe_bytes)
    return path


@pytest.fixture
def rules():
    from tp2.scanner import compile_rules

    return compile_rules()
