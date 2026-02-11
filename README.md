# IOC Analyzer - Script d'automatisation SOC

Script Python pour l'extraction et l'enrichissement automatique d'Indicateurs de Compromission (IOCs) depuis des rapports de threat intelligence, alertes de sécurité, ou tout texte contenant des IOCs.

## 🎯 Fonctionnalités

- **Extraction automatique** de 7 types d'IOCs :
  - Adresses IPv4
  - Domaines
  - URLs
  - Hashes (MD5, SHA1, SHA256)
  - Adresses email

- **Enrichissement via APIs gratuites** :
  - **AbuseIPDB** : Réputation des IPs
  - **VirusTotal** : Analyse de hashes/fichiers

- **Génération de rapports** :
  - Format JSON (pour intégration)
  - Format HTML (pour visualisation)

## 📋 Prérequis

- Python 3.7+
- Bibliothèque `requests`

## 🚀 Installation

```bash
# Cloner ou télécharger le projet
git clone [votre-repo]
cd ioc-analyzer

# Installer les dépendances
pip install -r requirements.txt

# Rendre le script exécutable (Linux/Mac)
chmod +x ioc_analyzer.py
```

## 🔑 Configuration des clés API (Optionnel mais recommandé)

### AbuseIPDB (Gratuit - 1000 requêtes/jour)

1. Créer un compte sur https://www.abuseipdb.com/
2. Aller dans "API" → Copier votre clé
3. Utiliser avec `--abuse VOTRE_CLE`

### VirusTotal (Gratuit - 4 requêtes/minute)

1. Créer un compte sur https://www.virustotal.com/
2. Profil → "API Key" → Copier votre clé
3. Utiliser avec `--vt VOTRE_CLE`

**Note** : Le script fonctionne sans clés API mais les IOCs ne seront pas enrichis (extraction uniquement).

## 💻 Utilisation

### Analyse d'un fichier

```bash
python ioc_analyzer.py -i rapport_threat_intel.txt

# Avec enrichissement complet
python ioc_analyzer.py -i rapport.txt --vt VT_KEY --abuse ABUSE_KEY

# Spécifier le nom de sortie
python ioc_analyzer.py -i rapport.txt -o mon_analyse
```

### Analyse de texte direct

```bash
python ioc_analyzer.py -t "Suspicious activity from 45.142.120.10 with hash 44d88612fea8a8f36de82e1278abb02f"
```

### Extraction uniquement (sans enrichissement)

```bash
python ioc_analyzer.py -i rapport.txt --no-enrich
```

## 📊 Exemples de sortie

### Rapport JSON (ioc_report.json)
```json
{
  "timestamp": "2024-02-04T14:30:00",
  "total_iocs": 12,
  "summary": {
    "malicious": 3,
    "suspicious": 2,
    "clean": 1,
    "unknown": 6
  },
  "iocs": [
    {
      "ioc": "45.142.120.10",
      "type": "ipv4",
      "reputation": "malicious",
      "sources": [
        {
          "name": "AbuseIPDB",
          "score": 100,
          "reports": 45
        }
      ]
    }
  ]
}
```

### Rapport HTML
Le rapport HTML contient :
- **Dashboard** avec statistiques visuelles
- **Tableau détaillé** de tous les IOCs
- **Badges de couleur** selon la réputation
- Interface responsive et professionnelle

## 🧪 Test avec les exemples fournis

```bash
# Test rapide sans APIs
python ioc_analyzer.py -i examples/example_threat_report.txt --no-enrich

# Test avec enrichissement (nécessite les clés API)
python ioc_analyzer.py -i examples/example_threat_report.txt --vt YOUR_VT_KEY --abuse YOUR_ABUSE_KEY
```

## 🔍 Use Cases en SOC

1. **Analyse rapide d'alertes** : Copier-coller une alerte et obtenir tous les IOCs
2. **Triage d'emails de phishing** : Extraire et vérifier les IPs/domaines suspects
3. **Parsing de rapports threat intel** : Automatiser l'extraction depuis des bulletins
4. **Enrichissement batch** : Vérifier rapidement la réputation d'une liste d'IOCs
5. **Documentation d'incidents** : Générer des rapports HTML professionnels

## 📁 Structure du projet

```
ioc-analyzer/
├── 📄 ioc_analyzer.py          # Script principal (420 lignes)
├── 📄 requirements.txt          # Dépendances Python
├── 📄 README.md                 # Documentation principale
├── 📄 LICENSE                   # Licence MIT
├── 📄 .gitignore               # Git ignore
│
├── 📁 docs/                     # Documentation complète
│   ├── QUICKSTART.md            # Guide de démarrage rapide
│   └── TODO.md                  # Améliorations futures
│
├── 📁 examples/                 # Fichiers de test
│   ├── example_edr_report.txt
│   └── example_threat_report.txt
│
├── 📁 outputs/                  # Rapports générés (gitignored)
│   ├── *.html                   # Rapports HTML
│   └── *.json                   # Rapports JSON
│
├── 📁 screenshots/              # Screenshots pour documentation
│   ├── analyse_example_edr_report.png
│   ├── analyse_example_threat_report.png
│   └── README.md
│
└── 📁 config/                   # Configuration
    └── config.example.py        # Exemple de configuration
```

## ⚙️ Options avancées

```
Options:
  -h, --help            Afficher l'aide
  -i INPUT              Fichier d'entrée à analyser
  -t TEXT               Texte à analyser directement
  --vt VT_KEY           Clé API VirusTotal
  --abuse ABUSE_KEY     Clé API AbuseIPDB
  -o OUTPUT             Nom de base pour les fichiers de sortie
  --no-enrich           Désactiver l'enrichissement (extraction seule)
```

## 🛡️ Sécurité

- Les clés API ne sont **jamais** stockées dans le code
- Passer les clés via arguments CLI ou variables d'environnement
- Respect des rate limits des APIs gratuites
- Whitelist de domaines légitimes pour réduire les faux positifs

## 📈 Améliorations possibles

- [ ] Support de plus d'APIs (OTX AlienVault, Shodan, URLhaus)
- [ ] Export CSV pour intégration Excel
- [ ] Mode batch avec fichier de config
- [ ] Intégration Slack/Teams pour notifications
- [ ] Support de regex personnalisées
- [ ] Cache local des résultats d'enrichissement
- [ ] Mode daemon pour surveillance continue

## 🤝 Contribution

Ce projet est un outil d'apprentissage pour analyste SOC. N'hésitez pas à :
- Proposer des améliorations
- Signaler des bugs
- Partager vos use cases

## 📝 License

Projet éducatif - Libre d'utilisation

## 👤 Auteur

Créé dans le cadre d'un portfolio SOC pour démontrer :
- Compétences en Python pour l'automatisation SOC
- Compréhension des IOCs et de la threat intelligence
- Capacité à créer des outils pratiques pour analyste

---

**Note** : Ce script est conçu à des fins éducatives et de démonstration. Pour un usage en production, ajouter une gestion d'erreurs plus robuste, du logging, et respecter les politiques de sécurité de votre organisation.
