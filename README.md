# TP2 – Triage automatisé de malware

Outil Python qui analyse des fichiers suspects : empreintes, IOC, imports (lief), règles YARA,
verdict LLM (OpenRouter ou Ollama) et rapports JSON + PDF.

```bash
poetry install
poetry run tp2 --samples DOSSIER --rules DOSSIER --out DOSSIER
```

- `--samples` : fichiers à analyser (parcours récursif)
- `--rules` : dossier de règles YARA (`.yar`, `.yara`) ; les règles personnelles sont toujours ajoutées
- `--out` : un `<sha256>.json` par échantillon ; les PDF sont dans `--out/reports/<sha256>.pdf`

> N'exécutez jamais un échantillon hors bac à sable. L'outil ne l'exécute pas : il le lit comme des octets.

## Architecture (`src/tp2/`)

| Module | Rôle |
|---|---|
| `metadata.py` | `get_file_metadata` : SHA-256, MD5, taille, type (python-magic), entropie de Shannon |
| `deobfuscate.py` | chaînes ASCII / UTF-16LE, décodage base64 et hex, vues XOR mono-octet (par « crib ») |
| `iocs.py` | `extract_iocs` (domaines, IP, URL, mutex, registre, chemins) et `find_flag` |
| `binary.py` | `parse_binary` : imports, exports, sections via lief (PE / ELF), jamais d'exception |
| `scanner.py`, `custom_rules.py` | `yara_scan` : règles du dossier `--rules` + 9 règles personnelles embarquées |
| `injection.py` | détection et neutralisation des injections de prompt |
| `llm.py` | `LLMClient` (OpenRouter / Ollama), `llm_triage`, validation pydantic de la sortie |
| `scoring.py` | score hybride, famille, mapping MITRE ATT&CK |
| `report.py` | `generate_report` : JSON conforme au contrat + PDF (fpdf2) |
| `pipeline.py`, `main.py` | orchestration d'un échantillon et CLI |

Aucune valeur d'un pack d'entraînement n'est codée en dur : tout est calculé à partir des octets.

## Sécurité de la chaîne LLM

1. **Données non fiables** : toute chaîne issue de l'échantillon est neutralisée (balises, caractères de
   contrôle, troncature) puis placée entre `<untrusted_data>` et `</untrusted_data>`. Le prompt système
   précise que ce contenu est une donnée, jamais une instruction.
2. **Le LLM ne décide pas seul** : un score objectif (0-10) est calculé depuis YARA, IOC, imports et
   entropie. Le score final reste dans `[base − 2, base + 3]`, et ne peut pas descendre sous la base si une
   injection est détectée. Tenter d'influencer l'analyse ajoute +3 à la base.
3. **Sortie validée** : JSON strict (pydantic), score entier borné 0-10, champs obligatoires, techniques
   MITRE au format `Txxxx(.xxx)`. Les IOC proposés par le LLM ne sont retenus que s'ils ont été extraits du
   fichier. Une réponse invalide est écartée.
4. **Jamais bloquant** : sans clé, sans réseau, en cas de quota (429) ou d'erreur, l'outil bascule
   sur un repli déterministe (YARA + IOC + imports) et coupe le LLM pour la suite du lot.

## Configuration du LLM

Créer un fichier `.env` à la racine (voir `env.example.txt`) :

```
OPENROUTER_API_KEY=sk-...
```

- Clé présente → OpenRouter (`meta-llama/llama-3.3-70b-instruct:free`, ~3 s entre deux appels).
- `TP2_LLM_BACKEND=ollama` → Ollama local (`qwen2.5:3b`).
- `TP2_LLM_BACKEND=none` ou pas de clé → repli déterministe uniquement.

Les empreintes, IOC, matches YARA, flag et le JSON ne dépendent jamais d'un appel réseau.

## Format de sortie

Les 13 champs du sujet, dans cet ordre : `sha256, md5, size, entropy, file_type, iocs{domains, ips, urls,
mutex, registry}, imports, yara_matches, family_guess, mitre_attack, llm_summary, score, flag`.
Listes triées et dédoublonnées (sortie déterministe) ; `flag` vaut `""` si aucun flag n'est trouvé.
Les chemins extraits figurent dans le PDF, pas dans le JSON.

## Tests

```bash
poetry run pytest
```

Un test (au moins) par fonction. Les échantillons sont fabriqués en mémoire (`tests/helpers.py`) :
aucun binaire dans le dépôt, y compris un PE32 valide construit octet par octet.
