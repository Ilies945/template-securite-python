"""Score hybride, familles et mapping MITRE ATT&CK.

Le score ne dépend jamais du seul LLM : une base est calculée à partir des
preuves objectives (YARA, IOC, imports, entropie) ; le LLM ne peut la faire
varier que dans une plage bornée.
"""
from __future__ import annotations

import re

# Catégories d'API suspectes -> (technique MITRE, capacité lisible)
API_CATEGORIES: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "network": ("T1071", "communication réseau (C2)", (
        "WSAStartup", "WSASocketA", "WSASocketW", "socket", "connect", "send", "recv",
        "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "HttpSendRequestA",
        "HttpSendRequestW", "WinHttpOpen", "WinHttpConnect", "gethostbyname", "getaddrinfo",
    )),
    "download": ("T1105", "téléchargement de charge utile", (
        "URLDownloadToFileA", "URLDownloadToFileW", "InternetReadFile", "WinHttpReadData",
        "DownloadString", "DownloadFile", "Invoke-WebRequest", "bitsadmin", "certutil",
    )),
    "execution": ("T1059", "exécution de commandes", (
        "CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW", "WinExec",
        "system", "execve", "execl", "popen",
    )),
    "injection": ("T1055", "injection de code dans un processus", (
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection",
        "SetThreadContext", "QueueUserAPC", "ptrace", "mprotect",
    )),
    "persistence": ("T1547", "persistance", (
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
        "CreateServiceA", "CreateServiceW",
    )),
    "evasion": ("T1497", "détection d'environnement d'analyse", (
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "GetTickCount", "Sleep",
    )),
    "crypto": ("T1486", "chiffrement de données", (
        "CryptEncrypt", "CryptAcquireContextA", "CryptAcquireContextW", "BCryptEncrypt",
        "CryptGenKey",
    )),
    "keylog": ("T1056", "capture de frappes", (
        "SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState",
    )),
    "files": ("T1083", "manipulation de fichiers", (
        "FindFirstFileA", "FindFirstFileW", "DeleteFileA", "DeleteFileW", "MoveFileExA",
    )),
}
# Faible poids : API banales qui ne prouvent rien seules.
WEAK_APIS = {"Sleep", "GetTickCount", "send", "recv", "socket", "connect", "system", "mprotect"}

YARA_MITRE_HINTS = (
    (re.compile(r"(?i)download|dropper|loader"), "T1105"),
    (re.compile(r"(?i)beacon|c2|network|http"), "T1071"),
    (re.compile(r"(?i)persist|autorun|run_?key"), "T1547"),
    (re.compile(r"(?i)inject|hollow"), "T1055"),
    (re.compile(r"(?i)ransom|crypt"), "T1486"),
    (re.compile(r"(?i)powershell|script|command|shell|exec"), "T1059"),
    (re.compile(r"(?i)anti|debug|evasion|vm|sandbox"), "T1497"),
    (re.compile(r"(?i)obfus|packed|inject"), "T1027"),
    (re.compile(r"(?i)keylog"), "T1056"),
    (re.compile(r"(?i)steal|cred|password"), "T1555"),
)
# Règles qui décrivent un artefact et non un comportement malveillant.
YARA_WEIGHTS = {"Custom_Hidden_Flag_Marker": 0.0, "Custom_Mutex_Marker": 1.0}
DEFAULT_YARA_WEIGHT = 2.0
TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

FAMILY_KEYWORDS = {
    "ransomware": re.compile(r"(?i)ransom|crypt|locker"),
    "dropper": re.compile(r"(?i)dropper|downloader|loader"),
    "backdoor": re.compile(r"(?i)backdoor|rat\b|reverse|shell|beacon|c2"),
    "stealer": re.compile(r"(?i)stealer|infostealer|cred|password|keylog"),
    "miner": re.compile(r"(?i)miner|xmrig|coin"),
    "worm": re.compile(r"(?i)worm|spread"),
}
ALLOWED_FAMILIES = ("benign", "dropper", "backdoor", "ransomware", "stealer", "miner", "worm", "trojan", "loader", "rat")
FAMILY_ALIASES = {
    "downloader": "dropper", "trojan downloader": "dropper", "reverse shell": "backdoor",
    "remote access trojan": "rat", "infostealer": "stealer", "info stealer": "stealer",
    "cryptominer": "miner", "crypto miner": "miner", "clean": "benign", "safe": "benign",
    "harmless": "benign", "legitimate": "benign", "bot": "backdoor", "botnet": "backdoor",
}


def categorize_imports(imports: list[str]) -> dict[str, list[str]]:
    wanted = {name.lower(): cat for cat, (_t, _c, apis) in API_CATEGORIES.items() for name in apis}
    found: dict[str, list[str]] = {}
    for imp in imports:
        cat = wanted.get(imp.lower())
        if cat:
            found.setdefault(cat, []).append(imp)
    return found


def infer_mitre(yara_meta: dict[str, dict], import_cats: dict[str, list[str]], iocs: dict) -> list[str]:
    techniques: set[str] = set()
    for name, meta in yara_meta.items():
        declared = str(meta.get("mitre", "") or meta.get("mitre_attack", ""))
        techniques.update(t for t in re.findall(r"T\d{4}(?:\.\d{3})?", declared))
        if not declared:
            techniques.update(t for rx, t in YARA_MITRE_HINTS if rx.search(name))
    for cat, apis in import_cats.items():
        if any(a not in WEAK_APIS for a in apis) or cat in {"network", "execution"}:
            techniques.add(API_CATEGORIES[cat][0])
    if iocs.get("urls") or iocs.get("domains") or iocs.get("ips"):
        techniques.add("T1071")
    if any(re.search(r"(?i)\\run(once)?\b|\\services\\|\\winlogon", k) for k in iocs.get("registry", [])):
        techniques.add("T1547")
    return sorted(techniques)


def base_score(
    yara_meta: dict[str, dict],
    iocs: dict,
    import_cats: dict[str, list[str]],
    entropy: float,
    injection: list[str],
) -> int:
    """Score 0-10 déterministe fondé uniquement sur des preuves objectives."""
    total = 0.0
    total += min(6.0, sum(YARA_WEIGHTS.get(n, DEFAULT_YARA_WEIGHT) for n in yara_meta))
    if iocs.get("urls"):
        total += 1.5
    if iocs.get("domains") or iocs.get("ips"):
        total += 1.0
    if iocs.get("mutex"):
        total += 1.0
    if any(re.search(r"(?i)\\run(once)?\b|\\services\\|\\winlogon", k) for k in iocs.get("registry", [])):
        total += 1.5
    elif iocs.get("registry"):
        total += 0.5
    strong = [c for c, apis in import_cats.items() if any(a not in WEAK_APIS for a in apis)]
    total += min(2.0, 0.5 * len(strong))
    if entropy >= 7.2:
        total += 1.0
    if injection:  # tenter de manipuler l'analyse est en soi un signal malveillant
        total += 3.0
    return max(0, min(10, round(total)))


def final_score(baseline: int, llm_score: int | None, injection: bool) -> int:
    """Le LLM est consultatif : son score est borné autour de la base objective."""
    if llm_score is None:
        return baseline
    floor = baseline if injection else max(0, baseline - 2)
    cap = min(10, baseline + 3)
    return max(floor, min(cap, int(llm_score)))


def normalize_family(raw: str | None) -> str | None:
    if not raw:
        return None
    fam = re.sub(r"[^a-z ]", "", str(raw).lower()).strip()
    fam = FAMILY_ALIASES.get(fam, fam)
    return fam if fam in ALLOWED_FAMILIES else None


def guess_family(
    yara_meta: dict[str, dict], import_cats: dict[str, list[str]], iocs: dict, score: int
) -> str:
    """Famille déterministe : mots-clés YARA d'abord, puis capacités observées."""
    if score <= 1 and not yara_meta:
        return "benign"
    names = " ".join(n for n in yara_meta if YARA_WEIGHTS.get(n, 1) > 0)
    for fam in ("ransomware", "stealer", "miner", "worm", "dropper"):
        if FAMILY_KEYWORDS[fam].search(names):
            return fam
    if "download" in import_cats:
        return "dropper"
    if FAMILY_KEYWORDS["backdoor"].search(names):
        return "backdoor"
    has_net = bool(iocs.get("urls") or iocs.get("domains") or iocs.get("ips") or "network" in import_cats)
    has_exec = "execution" in import_cats or any("Command_Execution" in n for n in yara_meta)
    if "crypto" in import_cats and any("Ransom" in n for n in yara_meta):
        return "ransomware"
    if "keylog" in import_cats:
        return "stealer"
    if "download" in import_cats or (has_net and has_exec and not import_cats.get("injection")):
        return "dropper"
    if has_net and (has_exec or "persistence" in import_cats):
        return "backdoor"
    if import_cats.get("injection"):
        return "loader"
    return "trojan" if score >= 4 else "benign"


def capabilities(import_cats: dict[str, list[str]], yara_meta: dict[str, dict], iocs: dict) -> list[str]:
    caps = {API_CATEGORIES[c][1] for c in import_cats if c != "files"}
    if iocs.get("urls") or iocs.get("domains") or iocs.get("ips"):
        caps.add(API_CATEGORIES["network"][1])
    if any(re.search(r"(?i)\\run(once)?\b", k) for k in iocs.get("registry", [])):
        caps.add(API_CATEGORIES["persistence"][1])
    for name, meta in yara_meta.items():
        desc = str(meta.get("description", "")).strip()
        if desc and YARA_WEIGHTS.get(name, 1) > 0:
            caps.add(desc[:120])
    return sorted(caps)
