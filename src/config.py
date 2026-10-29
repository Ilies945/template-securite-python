"""Configuration globale : chargement du .env et paramètres du pipeline."""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# Charge le .env situé à la racine du projet (là où se trouve pyproject.toml).
ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env")
load_dotenv()  # et celui du répertoire courant, au besoin

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_MODEL = os.environ.get("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct:free")
OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/chat")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:3b")

# Le palier gratuit d'OpenRouter est limité (50 req/jour) : timeout court,
# pas d'acharnement, et repli déterministe en cas d'échec.
LLM_TIMEOUT = float(os.environ.get("TP2_LLM_TIMEOUT", "20"))
MAX_PROMPT_STRINGS = 60
MAX_STRING_LEN = 200


def openrouter_key() -> str | None:
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    return key or None


def llm_backend() -> str:
    """openrouter (défaut si clé présente), ollama, ou none (repli seul)."""
    forced = os.environ.get("TP2_LLM_BACKEND", "").strip().lower()
    if forced in {"openrouter", "ollama", "none"}:
        return forced
    return "openrouter" if openrouter_key() else "none"
