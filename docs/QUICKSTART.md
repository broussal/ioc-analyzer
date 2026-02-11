# 🚀 Quick Start Guide - IOC Analyzer

## Installation en 2 minutes

```bash
# 1. Cloner le projet
cd ~/Bureau
git clone [votre-repo] ioc-analyzer
cd ioc-analyzer

# 2. Installer la dépendance
pip install requests

# 3. Tester avec l'exemple
python3 ioc_analyzer.py -i example_threat_report.txt --no-enrich
```

✅ Vous devriez voir 28 IOCs extraits et 2 fichiers générés !

## Utilisation quotidienne en SOC

### Scénario 1 : Alerte EDR
```bash
# Analyser rapidement avec enrichissement
python3 ioc_analyzer.py -i .\examples\example_edr_report.txt --abuse VOTRE_CLE
# → Vérification automatique de la réputation des IPs
```

### Scénario 2 : Rapport threat intel externe
```bash
# Parser un bulletin de sécurité
python3 ioc_analyzer.py -i .\examples\example_threat_report.txt -o bulletin_analysis
# → Extraction complète des IOCs pour votre SIEM
```

### Scénario 3 : Analyse rapide en CLI
```bash
# Pas besoin de fichier
python3 ioc_analyzer.py -t "Connexion suspecte depuis 45.142.120.10 vers malicious.tk"
```

## Obtenir les clés API GRATUITES (5 min)

### AbuseIPDB (recommandé pour les IPs)
1. https://www.abuseipdb.com/register
2. Vérifier votre email
3. API → Copier la clé
4. Utiliser : `--abuse VOTRE_CLE`
   
**Limite** : 1000 requêtes/jour (largement suffisant)

### VirusTotal (recommandé pour les hashes)
1. https://www.virustotal.com/gui/join-us
2. Se connecter avec Google/GitHub
3. Profil → API Key
4. Utiliser : `--vt VOTRE_CLE`

**Limite** : 4 requêtes/minute (attention au rate limit)

## Astuce pour éviter de taper les clés à chaque fois

Créer un alias dans votre `.bashrc` ou `.zshrc` :

```bash
# Ajouter dans ~/.bashrc
alias iocanalyze='python3 ~/ioc-analyzer/ioc_analyzer.py --vt VOTRE_VT_KEY --abuse VOTRE_ABUSE_KEY'

# Puis utiliser simplement :
iocanalyze -i rapport.txt
```

Ou créer un script wrapper :

```bash
#!/bin/bash
# ~/.local/bin/iocanalyze
python3 ~/ioc-analyzer/ioc_analyzer.py \
  --vt "votre_cle_vt" \
  --abuse "votre_cle_abuse" \
  "$@"
```

## Intégration dans votre workflow

### Export vers SIEM/SOAR
Le fichier JSON peut être importé directement dans :
- Splunk (via script Python)
- TheHive (création de cas)
- MISP (import d'IOCs)
- Cortex (analyse complémentaire)

### Avec votre Wazuh Lab
```bash
# Analyser les alertes Wazuh
python3 ioc_analyzer.py -i /var/ossec/logs/alerts/alerts.json --no-enrich
```

## Troubleshooting

**"ModuleNotFoundError: No module named 'requests'"**
```bash
pip install requests
# ou
pip3 install requests
```

**"Rate limit exceeded" (VirusTotal)**
→ Augmenter le `time.sleep()` dans le code ou attendre quelques minutes

**"Permission denied"**
```bash
chmod +x ioc_analyzer.py
```