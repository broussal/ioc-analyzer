# 🎯 GUIDE COMPLET DES IOCS - IOC Analyzer

## 📊 ENRICHISSEMENT PAR TYPE D'IOC

| Type | API utilisée | Temps | Résultats possibles |
|------|-------------|-------|---------------------|
| **IPv4** | AbuseIPDB | 0.5s/IP | 🔴 MALICIOUS (≥ 10%) • 🟠 SUSPICIOUS (≥ 5%) • 🟢 CLEAN (< 5%) |
| **Domain** | VirusTotal | 15s/domain | 🔴 MALICIOUS (> 5 détections) • 🟠 SUSPICIOUS (1-5) • 🟢 CLEAN (0) |
| **URL** | VirusTotal | 15s/URL | 🔴 MALICIOUS (> 5 détections) • 🟠 SUSPICIOUS (1-5) • 🟢 CLEAN (0) |
| **Email** | VirusTotal (via domaine) | 15s/email | 🔴 MALICIOUS (domaine malveillant) • 🟠 SUSPICIOUS (domaine suspect) • ⚪ UNKNOWN (domaine clean) |
| **MD5/SHA1/SHA256** | VirusTotal | 15s/hash | 🔴 MALICIOUS (> 5 détections) • 🟠 SUSPICIOUS (1-5) • 🟢 CLEAN (0) |

---

## 🎯 NORMALISATION DES DOMAINES

L'outil normalise automatiquement les domaines vers leur **racine** :

```
www.evil.com     → evil.com
mail.evil.com    → evil.com
subdomain.evil.com → evil.com

Résultat : 1 seule entrée "evil.com" dans le rapport
Avantage : 1 seule analyse VirusTotal au lieu de 3
```

**Pourquoi ?**
- Évite les duplicatas
- Réduit le nombre de requêtes API
- Résultats cohérents (même réputation pour tous les sous-domaines)

---

## 🔧 REFANGING AUTOMATIQUE

L'outil refang automatiquement les IOCs defangées :

### URLs
```
hxxp://malware.com    → http://malware.com
hxxps://evil.net      → https://evil.net
http[:]//bad.org      → http://bad.org
```

### Domaines et IPs
```
evil[.]com            → evil.com
192[.]168[.]1[.]1     → 192.168.1.1
[.]tk                 → .tk
```

### Emails
```
attacker[@]evil.com   → attacker@evil.com
phishing[at]bad.net   → phishing@bad.net
```

---

## 📋 FICHIERS D'EXEMPLE FOURNIS

### 1️⃣ example_threat_report.txt

**Contenu** :
- 8 IPs légitimes (Google DNS, Cloudflare DNS, etc.)
- 3 familles de malware (WannaCry, Ryuk, Emotet) = 4 hashes 
- 6 domaines suspects
- 4 URLs malveillantes
- 1 email suspect

**IOCs extraits** : 28 IOCs

**Temps d'analyse** : ~420 secondes (avec enrichissement)

**Résultats attendus** :
```
🔴 11 MALICIOUS  (hashes, domaines, URL, emails malveillants)
🟠 2 SUSPICIOUS  (URL suspectes)
🟢 14 CLEAN      (IPs et domaines connus)
⚪ 1 UNKNOWN     (email non whitelistée)
```

**Utilisation** :
```bash
python ioc_analyzer.py -i examples/example_threat_report.txt
```

---

### 2️⃣ example_edr_report.txt

**Contenu** :
- 1 malware (TrickBot)
- 2 hashes (SHA256 + MD5)
- 1 domaine C2

**IOCs extraits** : 4 IOCs

**Temps d'analyse** : ~30 secondes

**Résultats attendus** :
```
🔴 4 MALICIOUS
🟠 0 SUSPICIOUS
🟢 0 CLEAN
⚪ 0 UNKNOWN
```

**Utilisation** :
```bash
python ioc_analyzer.py -i examples/example_edr_report.txt
```

---

## 🎯 IOCS GARANTIES - TOUJOURS LES MÊMES RÉSULTATS

### ✅ IPs TOUJOURS CLEAN

Ces IPs de services publics sont **toujours** marquées CLEAN (score AbuseIPDB = 0) :

```
8.8.8.8              # Google DNS
8.8.4.4              # Google DNS secondaire
1.1.1.1              # Cloudflare DNS
1.0.0.1              # Cloudflare DNS secondaire
208.67.222.222       # OpenDNS
9.9.9.9              # Quad9
```

**Pourquoi ?** Ces IPs sont des services publics légitimes, jamais signalées.

---

### ✅ HASHES TOUJOURS MALICIOUS

Ces hashes de malware connus sont **toujours** détectés par VirusTotal :

**WannaCry Ransomware**
```
MD5: db349b97c37d22f5ea1d1841e3c89eb4
SHA256: ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa
Détections: 60-70/90 antivirus
```

**Ryuk Ransomware**
```
SHA256: bf575ce1c9425bc44f5cabbc34366e0e92ef369db0a8b69942c5bdb1cca9b800
Détections : 50-65/90 antivirus
```

**Emotet Trojan**
```
MD5: 3e6de9e2baacf930949647c399818e7a
SHA256: 23873bf2670cf64c2440058130548d4e4da412dd2750a5ce15a6f4db71ee6419
Détections : 50-60/90 antivirus
```

**TrickBot**
```
MD5: beee6b598d006a6f6fc93f6b8764715f
SHA256: b7209653e226c798ca29343912cf21f22b7deea4876a8cadb88803541988e941
Détections : 50-60/90 antivirus
```

**Pourquoi ?** Ces malwares sont historiques et **jamais retirés** des bases VirusTotal.

---

## 🧪 TESTS RECOMMANDÉS

### Test rapide (30 secondes) ⭐ DÉMARRAGE

```bash
python ioc_analyzer.py -i examples/example_edr_report.txt
```

**Résultat** : 4🔴

**Objectif** : Vérifier que l'outil fonctionne correctement

---

### Test complet (420 secondes) 🔥 DÉMONSTRATION

```bash
python ioc_analyzer.py -i examples/example_threat_report.txt
```

**Résultat** : 11🔴 + 🟠2 + 14🟢 + 1⚪

**Objectif** : Voir toutes les catégories d'IOCs

---

### Test extraction seule (<5 secondes) ⚡ RAPIDE

```bash
python ioc_analyzer.py -i examples/example_threat_report.txt --no-enrich
```

**Résultat** : Tous les IOCs extraits, tous marqués UNKNOWN

**Objectif** : Vérifier l'extraction sans enrichissement

---

## 📊 SEUILS DE RÉPUTATION

### AbuseIPDB (IPs)
```
Score ≥ 10%  → 🔴 MALICIOUS
Score ≥ 5%   → 🟠 SUSPICIOUS
Score < 5%   → 🟢 CLEAN
```

**Note** : Les IPs de la whitelist (8.8.8.8, 1.1.1.1, etc.) sont directement marquées CLEAN sans requête API.

---

### VirusTotal (Domains, URLs, Hashes)
```
Détections > 5   → 🔴 MALICIOUS
Détections 1-5   → 🟠 SUSPICIOUS
Détections = 0   → 🟢 CLEAN
```

**Note** : Les domaines de la whitelist (google.com, microsoft.com, etc.) sont directement marqués CLEAN sans requête API.

---

### Emails (via analyse du domaine)
```
Domaine MALICIOUS    → 🔴 MALICIOUS
Domaine SUSPICIOUS   → 🟠 SUSPICIOUS
Domaine CLEAN        → ⚪ UNKNOWN
Domaine UNKNOWN      → ⚪ UNKNOWN
```

**Logique** :
- L'email lui-même n'est pas analysable directement
- On analyse le domaine de l'email
- Si le domaine est malveillant, l'email est marqué MALICIOUS
- Sinon, l'email reste UNKNOWN (pas assez d'infos)

---

## 🎨 CODE COULEUR DASHBOARD

```
🔴 MALICIOUS   : Confirmé dangereux (à bloquer immédiatement)
🟠 SUSPICIOUS  : Potentiellement dangereux (à investiguer)
🟢 CLEAN       : Confirmé légitime (services publics)
⚪ UNKNOWN     : Pas d'information disponible
```

---

## 📁 NETTOYAGE DES OUTPUTS

### PowerShell (Windows)
```powershell
# Supprimer tous les rapports
Remove-Item outputs\*.html, outputs\*.json

# Ou utiliser le script fourni
.\clean_outputs.ps1
```

### Bash (Linux/Mac)
```bash
# Supprimer tous les rapports
rm outputs/*.html outputs/*.json
```

---

## 🚀 TIPS & TRICKS

### 1. Utiliser config.py pour les clés API

Au lieu de :
```bash
python ioc_analyzer.py -i rapport.txt --vt VT_KEY --abuse ABUSE_KEY
```

Configurer une fois dans `config/config.py` :
```python
VIRUSTOTAL_API_KEY = "votre_clé_vt"
ABUSEIPDB_API_KEY = "votre_clé_abuse"
```

Puis simplement :
```bash
python ioc_analyzer.py -i rapport.txt
```

---

### 2. Mode extraction rapide pour vérifier le parsing

Avant de lancer l'enrichissement (long), vérifier que les IOCs sont bien extraits :

```bash
# Extraction seule (< 5 secondes)
python ioc_analyzer.py -i nouveau_rapport.txt --no-enrich

# Si OK, lancer l'enrichissement complet
python ioc_analyzer.py -i nouveau_rapport.txt
```

---

### 3. Nom de sortie personnalisé

Par défaut, les fichiers sont nommés d'après le fichier d'entrée :
```bash
python ioc_analyzer.py -i rapport_incident.txt
# Génère : outputs/analyse_rapport_incident.html
```

Personnaliser :
```bash
python ioc_analyzer.py -i rapport_incident.txt -o incident_phishing_2024
# Génère : outputs/incident_phishing_2024.html
```

---

## ⏱️ TEMPS D'ANALYSE (avec enrichissement)

Estimation basée sur les rate limits API :

```
1 IP       = 0.5 seconde   (AbuseIPDB)
1 Hash     = 15 secondes   (VirusTotal)
1 Domain   = 15 secondes   (VirusTotal)
1 URL      = 15 secondes   (VirusTotal)
1 Email    = 15 secondes   (VirusTotal via domaine)
```

**Exemples** :
- 3 IPs + 2 hashes = 1.5s + 30s = **~30 secondes**
- 5 IPs + 5 hashes + 3 domaines = 2.5s + 75s + 45s = **~2 minutes**
- 10 IOCs variés = **~2-3 minutes**

**Note** : Le mode `--no-enrich` est instantané (< 5 secondes) pour tous les fichiers.

---

## ❓ FAQ

### Pourquoi certains domaines sont UNKNOWN ?

Si VirusTotal n'a jamais analysé le domaine, il n'y a pas de données de réputation.
Cela arrive sourtout pour :
- Domaines très récents
- Domaines obscurs avec peu de trafic
- Domaines légitimes non connus

### Pourquoi normaliser les domaines ?

Sans normalisation :
```
www.evil.com    → Analyse VirusTotal (15s)
mail.evil.com   → Analyse VirusTotal (15s)
evil.com        → Analyse VirusTotal (15s)
Total : 45 secondes, 3 requêtes API
```

Avec normalisation :
```
www.evil.com    ┐
mail.evil.com   ├→ evil.com → Analyse VirusTotal (15s)
evil.com        ┘
Total : 15 secondes, 1 requête API
```

### Les IPs privées (192.168.x.x, 10.x.x.x) sont-elles analysées ?

Non, elles sont automatiquement détectées et **non analysées** (pas de requête AbuseIPDB).
Les IPs privées RFC 1918 ne sont pas routables sur Internet donc pas pertinentes pour AbuseIPDB.

### Que faire si j'atteins la limite API ?

**VirusTotal (4 req/min)** :
- Attendre 1 minute
- Ou utiliser `--no-enrich` pour extraction seule

**AbuseIPDB (1000 req/jour)** :
- Attendre le lendemain
- Ou créer un second compte

---

**🎯 Avec ce guide, vous maîtrisez tous les aspects de l'IOC Analyzer !** 🔐
