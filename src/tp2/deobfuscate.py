"""Extraction de chaînes et décodage léger des couches d'obfuscation.

Les échantillons cachent souvent leurs indicateurs : chaînes « wide » (UTF-16LE),
blobs base64 ou hexadécimaux, XOR mono-octet. Ce module produit des « vues »
textuelles du fichier pour que les extracteurs d'IOC et de flag les exploitent.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

ASCII_RUN = re.compile(rb"[\x09\x0a\x0d\x20-\x7e]{4,}")
WIDE_RUN = re.compile(rb"(?:[\x09\x0a\x0d\x20-\x7e]\x00){4,}")
B64_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
HEX_RUN = re.compile(r"(?:[0-9A-Fa-f]{2}){8,}")

# Motifs connus (>= 5 octets) servant de « crib » pour détecter un XOR mono-octet.
XOR_CRIBS = (
    b"http://",
    b"https://",
    b"ESGI{",
    b"Global\\",
    b"HKCU\\",
    b"HKLM\\",
    b"This program",
    b"cmd.exe",
    b"powershell",
)
XOR_SCAN_LIMIT = 8 * 1024 * 1024  # on ne cherche pas de XOR au-delà de 8 Mio
MAX_LAYER_DEPTH = 2


def extract_strings(data: bytes, min_len: int = 4) -> list[str]:
    """Chaînes ASCII puis UTF-16LE (ordre d'apparition dans chaque famille)."""
    out: list[str] = []
    for m in ASCII_RUN.finditer(data):
        s = m.group().decode("ascii")
        if len(s.strip()) >= min_len:
            out.append(s)
    for m in WIDE_RUN.finditer(data):
        raw = m.group()
        # Si l'octet précédent est un caractère ASCII, le premier « caractère wide »
        # est en fait la fin d'une chaîne ASCII et son 0x00 de terminaison.
        if m.start() > 0 and 0x20 <= data[m.start() - 1] <= 0x7E:
            raw = raw[2:]
        s = raw.decode("utf-16-le", errors="ignore")
        if len(s.strip()) >= min_len:
            out.append(s)
    return out


def _printable_ratio(blob: bytes) -> float:
    if not blob:
        return 0.0
    good = sum(1 for b in blob if 32 <= b < 127 or b in (9, 10, 13))
    return good / len(blob)


def _wide_ratio(blob: bytes) -> float:
    """Part d'octets pairs imprimables si le blob ressemble à de l'UTF-16LE."""
    if len(blob) < 8 or len(blob) % 2:
        return 0.0
    odd_zero = sum(1 for b in blob[1::2] if b == 0) / (len(blob) // 2)
    if odd_zero < 0.9:
        return 0.0
    return _printable_ratio(blob[0::2])


def _is_texty(blob: bytes) -> bool:
    return len(blob) >= 8 and (_printable_ratio(blob) >= 0.9 or _wide_ratio(blob) >= 0.9)


def decode_blobs(strings: list[str], depth: int = 0) -> list[bytes]:
    """Décode les blobs base64 / hex qui donnent un contenu textuel."""
    found: list[bytes] = []
    if depth >= MAX_LAYER_DEPTH:
        return found
    for s in strings:
        candidates: list[bytes] = []
        for m in B64_RUN.finditer(s):
            token = m.group().rstrip("=")
            token += "=" * (-len(token) % 4)
            try:
                candidates.append(base64.b64decode(token, validate=True))
            except (binascii.Error, ValueError):
                continue
        for m in HEX_RUN.finditer(s):
            try:
                candidates.append(bytes.fromhex(m.group()))
            except ValueError:
                continue
        for blob in candidates:
            if _is_texty(blob):
                found.append(blob)
                found.extend(decode_blobs(extract_strings(blob, 6), depth + 1))
    return found


def xor_views(data: bytes) -> list[tuple[int, bytes]]:
    """Vues déchiffrées pour chaque clé XOR mono-octet dont un crib est présent."""
    if len(data) > XOR_SCAN_LIMIT:
        data = data[:XOR_SCAN_LIMIT]
    views: list[tuple[int, bytes]] = []
    for key in range(1, 256):
        hit = any(data.find(bytes(b ^ key for b in crib)) != -1 for crib in XOR_CRIBS)
        if hit:
            view = data.translate(bytes(i ^ key for i in range(256)))
            # Les zéros de bourrage non chiffrés deviennent des octets « clé » : on les
            # remet à zéro pour qu'ils ne se collent pas aux chaînes voisines.
            view = re.sub(re.escape(bytes([key])) + b"{2,}", b"\x00", view)
            views.append((key, view))
    return views


@dataclass
class Texts:
    """Chaînes extraites : `plain` (fichier + couches décodées) et `strict` (vues XOR)."""

    plain: list[str] = field(default_factory=list)
    strict: list[str] = field(default_factory=list)


def collect_texts(data: bytes) -> Texts:
    texts = Texts()
    texts.plain = extract_strings(data)
    for blob in decode_blobs(texts.plain):
        texts.plain.extend(extract_strings(blob, 4))
        if _wide_ratio(blob) >= 0.9:  # base64 d'un texte UTF-16LE (PowerShell -enc)
            texts.plain.append(blob.decode("utf-16-le", errors="ignore"))
    for _key, view in xor_views(data):
        texts.strict.extend(extract_strings(view, 5))
    return texts
