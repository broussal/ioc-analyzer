# TODO - Améliorations futures

## 🎯 Priorité HAUTE (Impact immédiat)

- [ ] **Ajout d'OTX AlienVault API** (gratuite, excellente pour la threat intel)
  - Fournit contexte sur les IPs/domaines/hashes
  - Informations sur les campagnes malware associées
  
- [ ] **Support IPv6**
  - Ajouter regex pour IPv6
  - Adapter l'enrichissement
  
- [ ] **Détection de CVEs**
  - Regex pour format CVE-YYYY-XXXXX
  - Enrichissement via NVD API

- [ ] **Export CSV**
  - Format Excel-friendly
  - Colonnes : IOC, Type, Reputation, Score, Sources
  - Utile pour partage avec équipe non-technique

## 📊 Priorité MOYENNE (Amélioration workflow)

- [ ] **Mode batch/config file**
  ```yaml
  # config.yaml
  apis:
    virustotal: key123
    abuseipdb: key456
  inputs:
    - alert1.txt
    - alert2.txt
  ```

- [ ] **Cache local avec SQLite**
  - Éviter de re-requêter les mêmes IOCs
  - Historique des analyses
  - Suivi de l'évolution de la réputation

- [ ] **Filtres personnalisés**
  - Blacklist personnalisée (ignorer IPs internes)
  - Whitelist personnalisée (domaines connus)
  - Regex custom pour IOCs spécifiques

- [ ] **Intégration MISP**
  - Import direct dans MISP
  - Export au format MISP JSON
  - Création d'événements automatiques

## 🔧 Priorité BASSE (Nice to have)

- [ ] **Interface web simple (Flask)**
  - Upload de fichier via navigateur
  - Visualisation des résultats
  - Historique des analyses

- [ ] **Mode daemon/watch**
  - Surveiller un dossier
  - Analyser automatiquement les nouveaux fichiers
  - Notifications Slack/Teams

- [ ] **Support de formats structurés**
  - Parsing direct de JSON/XML
  - Logs Syslog
  - PCAP (extraction d'IOCs réseau)

- [ ] **Indicateurs TLP (Traffic Light Protocol)**
  - Marquer les IOCs selon sensibilité
  - Filtrage selon niveau TLP

- [ ] **Machine Learning basique**
  - Scoring personnalisé basé sur historique
  - Détection de patterns suspects

## 🔒 Sécurité & Production

- [ ] **Logging robuste**
  - Fichiers de logs rotatifs
  - Niveaux : DEBUG, INFO, WARNING, ERROR
  - Traçabilité des analyses

- [ ] **Gestion d'erreurs améliorée**
  - Try/except plus granulaires
  - Messages d'erreur utilisateur-friendly
  - Retry logic pour APIs

- [ ] **Tests unitaires**
  - pytest pour chaque fonction
  - Mocking des APIs
  - Coverage > 80%

- [ ] **Variables d'environnement**
  - Charger clés API depuis .env
  - Support de python-dotenv
  
- [ ] **Rate limiting intelligent**
  - Détection automatique des limites
  - Queue pour requêtes en masse
  - Fallback si API down

## 📚 Documentation

- [ ] **Guide de contribution**
  - CONTRIBUTING.md
  - Code of conduct
  - Templates d'issues GitHub

- [ ] **Exemples avancés**
  - Intégration dans workflow SOC
  - Scripts wrapper personnalisés
  - Cas d'usage réels

- [ ] **Vidéo démo**
  - Screencast de 3-5 minutes
  - Cas d'usage concret
  - Héberger sur YouTube/LinkedIn

## 💡 Idées exploratoires

- [ ] **Support de langues étrangères**
  - Détection d'IOCs dans texte cyrillique, chinois, etc.
  
- [ ] **Analyse de timeline**
  - Corrélation temporelle des IOCs
  - Graphe de relations
  
- [ ] **Integration avec Wazuh**
  - Plugin Wazuh custom
  - Enrichissement automatique des alertes
