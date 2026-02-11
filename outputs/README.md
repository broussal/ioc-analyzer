# 📁 Dossier outputs/

Ce dossier contient les rapports générés par IOC Analyzer.

## 📊 Fichiers générés

Lors de l'exécution du script, les fichiers suivants sont créés ici :

### Rapports JSON
```
nom_rapport.json
```
- Format machine-readable
- Parfait pour intégration avec d'autres outils
- Contient tous les détails des IOCs enrichis

### Rapports HTML
```
nom_rapport.html
```
- Format humain-readable
- Dashboard visuel avec statistiques
- Tableau détaillé des IOCs
- Prêt pour partage/présentation

## 🗑️ Nettoyage

### Commande rapide (PowerShell)
```powershell
del outputs\*.html, outputs\*.json
```

### Script automatique
```powershell
.\clean_outputs.ps1
```

## ⚠️ Important

- Ce dossier est dans `.gitignore`
- Les rapports ne seront **PAS** commitées sur GitHub
- Seul `.gitkeep` est versionné (pour préserver la structure)

## 📝 Exemple d'utilisation

```powershell
# Générer un rapport
python ioc_analyzer.py -i examples/test_clean_vs_malicious.txt -o mon_rapport

# Résultat :
outputs/
├── mon_rapport.json
└── mon_rapport.html

# Ouvrir le rapport
start outputs\mon_rapport.html
```

## ✅ Bonnes pratiques

1. **Nettoyer régulièrement** : `del outputs\*.html, outputs\*.json`
2. **Noms explicites** : `-o phishing_analysis` plutôt que `-o test`
3. **Archiver si important** : Copier ailleurs avant nettoyage

---

**Note** : Le `.gitkeep` est nécessaire pour que Git suive ce dossier vide.
