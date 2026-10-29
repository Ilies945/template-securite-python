"""Extraction d'indicateurs de compromission (IOC) et du flag.

Aucune valeur n'est codée en dur : tout provient de regex appliquées aux chaînes
du fichier (ASCII, UTF-16LE, couches base64/hex et XOR mono-octet décodées).
"""
from __future__ import annotations

import ipaddress
import re

from .deobfuscate import Texts, collect_texts, extract_strings

URL_RE = re.compile(r"(?i)\b(?:https?|ftps?|tcp|wss?)://[^\s\"'<>\\^`{}|\x00-\x1f]+")
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
DOMAIN_RE = re.compile(r"(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w-])")
MUTEX_RE = re.compile(r"(?:Global|Local|Session\\\d+)\\[A-Za-z0-9_.\-{}$@!#%&+=~]{2,}")
REGISTRY_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)"
    r"|HK(?:LM|CU|CR|U|CC))\\[^\x00-\x1f\"'<>|*?]+"
)
REGISTRY_BARE_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_\\])(?:SOFTWARE|SYSTEM)\\(?:Microsoft\\Windows(?: NT)?\\CurrentVersion"
    r"\\(?:Run|RunOnce|Winlogon|Policies)|CurrentControlSet\\Services)[^\x00-\x1f\"'<>|*?]*"
)
WIN_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\s]*"
    r"|%[A-Za-z_()]{3,20}%\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\s]*"
    r"|\\\\[A-Za-z0-9_.$-]+\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\s]*)"
)
UNIX_PATH_RE = re.compile(
    r"(?<![\w/.:~-])/(?:etc|tmp|var|usr|bin|sbin|home|root|opt|dev|proc|lib|lib64|run|srv|mnt|boot)"
    r"/[\w.@%+~/-]+"
)
FLAG_RE = re.compile(r"ESGI\{[^{}\r\n\x00]{1,200}\}")

# Extensions de fichiers qui ressemblent à des TLD : jamais des domaines.
EXTENSION_TLDS = {
    "dll", "exe", "sys", "drv", "ocx", "cpl", "scr", "bat", "cmd", "ps1", "vbs", "vbe", "js",
    "txt", "log", "dat", "tmp", "ini", "cfg", "conf", "json", "xml", "html", "htm", "php",
    "asp", "aspx", "jsp", "py", "pyc", "sh", "so", "pl", "md", "ps", "db", "ko", "lib", "obj",
    "pdb", "map", "bin", "cab", "msi", "lnk", "tmpl", "rs", "go", "cs", "vb", "ts", "jar",
    "class", "gz", "zip", "rar", "png", "jpg", "jpeg", "gif", "ico", "bmp", "dmp", "key",
    "pem", "crt", "cer", "plist", "res", "rc", "inf", "reg", "hlp", "mof", "mui", "nls",
    "sql", "yml", "yaml", "toml", "sample", "text", "data", "rdata", "idata", "pdata", "rsrc",
    "reloc", "tls", "bss", "comment", "symtab", "strtab",
}
# TLD plausibles : gTLD courants + domaines réservés (RFC 2606/6761) utilisés en TP.
COMMON_TLDS = {
    "com", "net", "org", "info", "biz", "xyz", "top", "online", "site", "club", "app", "dev",
    "cloud", "tech", "pro", "name", "mobi", "live", "shop", "store", "fun", "space", "website",
    "link", "click", "work", "today", "world", "network", "systems", "email", "edu", "gov",
    "mil", "int", "icu", "vip", "life", "press", "host", "stream", "download", "win", "bid",
    "loan", "review", "trade", "party", "science", "date", "faith", "racing", "cricket",
    "accountant", "digital", "services", "solutions", "support", "center", "agency", "zone",
    "ninja", "guru", "rocks", "world", "city", "company", "group", "global", "plus",
    "test", "example", "invalid", "local", "localhost", "onion", "lan", "internal", "corp",
    "home", "lab", "intranet",
}
DOTNET_ROOTS = {"system", "microsoft", "windows", "newtonsoft", "mscorlib", "mono", "xunit"}
BENIGN_HOSTS = {
    "schemas.microsoft.com", "www.w3.org", "schemas.xmlsoap.org", "ns.adobe.com", "purl.org",
    "schemas.openxmlformats.org", "www.verisign.com", "ocsp.digicert.com", "crl.microsoft.com",
    "www.microsoft.com", "go.microsoft.com", "www.digicert.com",
}
NOISY_UNIX_PREFIXES = ("/lib64/ld-linux", "/lib/ld-linux", "/lib/x86_64-linux-gnu")
TRAILING = ".,;:)]}>'\"!?"


def _clean(token: str) -> str:
    return token.rstrip(TRAILING + " \t")


def _valid_ip(candidate: str) -> bool:
    try:
        ip = ipaddress.IPv4Address(candidate)
    except ValueError:
        return False
    return not ip.is_unspecified


def _valid_domain(candidate: str) -> bool:
    domain = candidate.lower().strip(".")
    labels = domain.split(".")
    if len(labels) < 2 or len(domain) > 253 or domain in BENIGN_HOSTS:
        return False
    tld = labels[-1]
    if tld in EXTENSION_TLDS or labels[0] in DOTNET_ROOTS:
        return False
    if not (tld in COMMON_TLDS or len(tld) == 2):
        return False
    if all(part.isdigit() for part in labels):  # une IP, pas un domaine
        return False
    return True


def _host_of(url: str) -> str:
    rest = url.split("://", 1)[1]
    host = re.split(r"[/?#]", rest, maxsplit=1)[0]
    host = host.rsplit("@", 1)[-1]
    if host.startswith("["):  # IPv6 : ignoré
        return ""
    return host.rsplit(":", 1)[0] if re.search(r":\d+$", host) else host


def _scan_strict(text: str, found: dict[str, set[str]]) -> None:
    """Motifs fortement structurés (utilisables aussi sur les vues XOR)."""
    for m in URL_RE.finditer(text):
        url = _clean(m.group())
        host = _host_of(url)
        if host.lower() in BENIGN_HOSTS or len(url) < 10:
            continue
        found["urls"].add(url)
        if _valid_ip(host):
            found["ips"].add(host)
        elif _valid_domain(host):
            found["domains"].add(host.lower())
    for m in MUTEX_RE.finditer(text):
        found["mutex"].add(_clean(m.group()))
    for m in REGISTRY_RE.finditer(text):
        found["registry"].add(_clean(m.group()))
    for m in REGISTRY_BARE_RE.finditer(text):
        found["registry"].add(_clean(m.group()))
    for m in WIN_PATH_RE.finditer(text):
        path = _clean(m.group())
        if len(path) >= 5:
            found["paths"].add(path)
    for m in UNIX_PATH_RE.finditer(text):
        path = _clean(m.group())
        if not path.startswith(NOISY_UNIX_PREFIXES):
            found["paths"].add(path)


def _scan_loose(text: str, found: dict[str, set[str]]) -> None:
    """IP et domaines isolés : seulement sur les chaînes réelles du fichier."""
    for m in IPV4_RE.finditer(text):
        if _valid_ip(m.group()):
            found["ips"].add(m.group())
    for m in DOMAIN_RE.finditer(text):
        if _valid_domain(m.group()):
            found["domains"].add(m.group().lower())


def extract_iocs_from_texts(texts: Texts) -> dict[str, list[str]]:
    found: dict[str, set[str]] = {k: set() for k in ("domains", "ips", "urls", "mutex", "registry", "paths")}
    for text in texts.plain:
        _scan_strict(text, found)
        _scan_loose(text, found)
    for text in texts.strict:
        _scan_strict(text, found)
    # Une clé « nue » déjà contenue dans une clé complète n'est pas un indicateur distinct.
    found["registry"] = {
        k for k in found["registry"]
        if k.startswith(("HK", "hk")) or not any(k.lower() in other.lower() for other in found["registry"] if other != k)
    }
    return {key: sorted(values) for key, values in found.items()}


def extract_iocs(data: bytes) -> dict[str, list[str]]:
    """Domaines, IP, URLs, mutex, clés de registre et chemins (listes triées, sans doublon)."""
    return extract_iocs_from_texts(collect_texts(data))


def find_flag(data: bytes, texts: Texts | None = None) -> str:
    """Cherche un flag `ESGI{...}` : brut, UTF-16LE, base64/hex, XOR mono-octet, inversé, ROT13."""
    import codecs

    texts = texts or collect_texts(data)
    for text in (*texts.plain, *texts.strict):
        if m := FLAG_RE.search(text):
            return m.group()
    for text in extract_strings(data[::-1]):  # chaîne écrite à l'envers
        if m := FLAG_RE.search(text):
            return m.group()
    for text in texts.plain:  # ROT13 d'une chaîne en clair
        if m := FLAG_RE.search(codecs.decode(text, "rot13")):
            return m.group()
    return ""
