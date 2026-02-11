# 🔑 Configuration des clés API - Guide rapide

## Option 1 : Via CLI (méthode actuelle)

```bash
python ioc_analyzer.py -i test.txt --abuse VOTRE_CLE_ABUSE --vt VOTRE_CLE_VT
```

**Avantage** : Aucune configuration nécessaire
**Inconvénient** : Il faut taper les clés à chaque fois

---

## Option 2 : Via config.py (RECOMMANDÉ) ✨

### Étape 1 : Créer le fichier config.py

**Dans le dossier `config/`, créer un nouveau fichier `config.py`** :

```python
# config/config.py
# ⚠️ NE JAMAIS COMMITER CE FICHIER SUR GITHUB !

# Clé API AbuseIPDB (gratuit 1000 req/jour)
# Obtenir sur : https://www.abuseipdb.com/
ABUSEIPDB_API_KEY = "vraie_cle_abuseipdb_ici"

# Clé API VirusTotal (gratuit 500 req/jour)
# Obtenir sur : https://www.virustotal.com/
VIRUSTOTAL_API_KEY = "vraie_cle_virustotal_ici"
```

### Étape 2 : Copier les vraies clés

Remplacer les textes par les vraies clés :
```python
ABUSEIPDB_API_KEY = "XXX"
VIRUSTOTAL_API_KEY = "XXX"
```

### Étape 3 : Utiliser sans taper les clés ! 🎉

```bash
# Plus besoin de --abuse et --vt !
python ioc_analyzer.py -i test.txt

# Le script charge automatiquement les clés depuis config/config.py
```
