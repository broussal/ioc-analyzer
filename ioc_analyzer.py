#!/usr/bin/env python3
"""
IOC Analyzer - Script d'automatisation SOC
Extrait et enrichit des Indicateurs de Compromission (IOCs) depuis du texte
"""

import re
import json
import requests
import argparse
from datetime import datetime
from typing import Dict, List, Set
import time
import os
import webbrowser
from pathlib import Path
import base64

# Tentative d'import des clés API depuis config/config.py (optionnel)
try:
    from config.config import ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY
    DEFAULT_ABUSE_KEY = ABUSEIPDB_API_KEY
    DEFAULT_VT_KEY = VIRUSTOTAL_API_KEY
except ImportError:
    # Pas de fichier config.py trouvé, utilisation via CLI uniquement
    DEFAULT_ABUSE_KEY = None
    DEFAULT_VT_KEY = None

# ============================================================================
# CONSTANTES GLOBALES - Éviter la duplication
# ============================================================================

# TLDs valides (liste blanche IANA)
VALID_TLDS = {
    # gTLDs génériques
    'com', 'net', 'org', 'edu', 'gov', 'mil', 'int',
    'aero', 'asia', 'biz', 'cat', 'coop', 'info', 'jobs',
    'mobi', 'museum', 'name', 'post', 'pro', 'tel', 'travel',
    # New gTLDs populaires
    'xyz', 'top', 'site', 'online', 'tech', 'store', 'web',
    'space', 'club', 'host', 'press', 'website', 'live', 'studio',
    'app', 'dev', 'cloud', 'io', 'ai', 'sh', 'co', 'me',
    # ccTLDs (country codes) - principaux
    'fr', 'de', 'uk', 'us', 'ca', 'au', 'jp', 'cn', 'ru', 'br',
    'es', 'it', 'nl', 'be', 'ch', 'se', 'no', 'dk', 'fi', 'pl',
    'cz', 'at', 'pt', 'gr', 'ie', 'nz', 'za', 'in', 'mx', 'ar',
    'cl', 'kr', 'tw', 'hk', 'sg', 'my', 'th', 'vn', 'id',
    # TLDs gratuits suspects mais valides
    'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'ws', 'to',
    # Autres
    'onion'  # Tor
}

# Domaines légitimes connus (vérification EXACTE uniquement)
KNOWN_GOOD_DOMAINS = {
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'github.com', 'stackoverflow.com', 'linkedin.com', 'facebook.com',
    'twitter.com', 'instagram.com', 'youtube.com', 'cloudflare.com',
    'akamai.com', 'fastly.com', 'azure.com', 'amazonaws.com',
    'office.com', 'live.com', 'outlook.com', 'hotmail.com',
    'gmail.com', 'yahoo.com', 'protonmail.com', 'tutanota.com',
    'opendns.com', 'quad9.net'
}

# IPs légitimes connues
KNOWN_GOOD_IPS = {
    '8.8.8.8', '8.8.4.4',  # Google DNS
    '1.1.1.1', '1.0.0.1',  # Cloudflare DNS
    '208.67.222.222', '208.67.220.220',  # OpenDNS
    '9.9.9.9',  # Quad9
}

class IOCExtractor:
    """Classe pour extraire les IOCs depuis du texte"""
    
    def __init__(self):
        # Regex patterns pour différents types d'IOCs
        self.patterns = {
            'ipv4': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
            'url': r'https?://[^\s<>"{}|\\^`\[\]]+',
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        }
    
    def refang(self, text: str) -> str:
        """
        Refang des IOCs defangés dans les rapports SOC
        Convertit les IOCs "safe" en format analysable
        """
        # URLs defangées
        text = re.sub(r'h..p\[?:]?\/\/\]?', 'http://', text, flags=re.IGNORECASE)
        text = re.sub(r'h..ps\[?:]?\/\/\]?', 'https://', text, flags=re.IGNORECASE)
        
        # IPs, domaines, emails defangés
        text = re.sub(r'\[\.\]', '.', text)
        text = re.sub(r'\[\:\]', ':', text)
        text = re.sub(r'\[dot\]', '.', text, flags=re.IGNORECASE)
        text = re.sub(r'\[@\]', '@', text)
        text = re.sub(r'\[at\]', '@', text, flags=re.IGNORECASE)
        
        return text
    
    def extract(self, text: str) -> Dict[str, Set[str]]:
        """Extrait tous les IOCs depuis le texte"""
        # Refang le texte avant extraction
        text = self.refang(text)
        
        iocs = {}
        
        for ioc_type, pattern in self.patterns.items():
            matches = set(re.findall(pattern, text, re.IGNORECASE))
            
            # Filtrage spécifique pour les domaines
            if ioc_type == 'domain':
                filtered = set()
                for m in matches:
                    # Extraire le TLD
                    tld = m.split('.')[-1].lower()
                    
                    # Vérifier si le TLD est valide (liste blanche)
                    if tld not in VALID_TLDS:
                        continue
                    
                    # Vérifier si c'est un chemin de fichier
                    if '\\' in m or '/' in m:
                        continue
                    
                    # Normaliser vers le domaine racine (2 dernières parties)
                    # www.google.com → google.com
                    # mail.microsoft.com → microsoft.com
                    parts = m.split('.')
                    if len(parts) >= 2:
                        root_domain = '.'.join(parts[-2:])
                        filtered.add(root_domain)
                
                matches = filtered
            
            if matches:
                iocs[ioc_type] = matches
        
        return iocs


class IOCEnricher:
    """Classe pour enrichir les IOCs via des APIs de threat intelligence"""
    
    def __init__(self, vt_api_key: str = None, abuseipdb_key: str = None):
        self.vt_api_key = vt_api_key
        self.abuseipdb_key = abuseipdb_key
        self.session = requests.Session()
    
    def is_legitimate_domain(self, domain: str) -> bool:
        """Vérifie si un domaine est légitime en extrayant le domaine racine"""
        domain_lower = domain.lower()
        
        # Extraire le domaine racine (2 dernières parties)
        # www.google.com → google.com
        # mail.microsoft.com → microsoft.com
        parts = domain_lower.split('.')
        if len(parts) >= 2:
            root_domain = '.'.join(parts[-2:])  # 2 dernières parties
            return root_domain in KNOWN_GOOD_DOMAINS
        
        return False
    
    def is_legitimate_ip(self, ip: str) -> bool:
        """Vérifie si une IP est légitime"""
        return ip in KNOWN_GOOD_IPS
    
    def enrich_ip(self, ip: str) -> Dict:
        """Enrichit une IP via AbuseIPDB (gratuit jusqu'à 1000 req/jour)"""
        result = {
            'ioc': ip,
            'type': 'ipv4',
            'reputation': 'unknown',
            'sources': []
        }
        
        # Check si IP légitime connue
        if self.is_legitimate_ip(ip):
            result['reputation'] = 'clean'
            result['sources'].append({
                'name': 'Known Good IP',
                'score': 0,
                'reports': 0
            })
            return result
        
        if not self.abuseipdb_key:
            return result
        
        try:
            url = f'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Accept': 'application/json',
                'Key': self.abuseipdb_key
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': '90'
            }
            
            response = self.session.get(url, headers=headers, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                abuse_score = data['data']['abuseConfidenceScore']
                
                if abuse_score >= 10:
                    result['reputation'] = 'malicious'
                elif abuse_score >= 5:
                    result['reputation'] = 'suspicious'
                else:
                    result['reputation'] = 'clean'
                
                result['sources'].append({
                    'name': 'AbuseIPDB',
                    'score': abuse_score,
                    'reports': data['data']['totalReports']
                })
            
            time.sleep(0.5)  # Rate limiting
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def enrich_hash(self, hash_value: str) -> Dict:
        """Enrichit un hash via VirusTotal (gratuit 4 req/min)"""
        result = {
            'ioc': hash_value,
            'type': 'hash',
            'reputation': 'unknown',
            'sources': []
        }
        
        if not self.vt_api_key:
            return result
        
        try:
            url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
            headers = {'x-apikey': self.vt_api_key}
            
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                
                if malicious > 5:
                    result['reputation'] = 'malicious'
                elif malicious > 0:
                    result['reputation'] = 'suspicious'
                else:
                    result['reputation'] = 'clean'
                
                result['sources'].append({
                    'name': 'VirusTotal',
                    'malicious': malicious,
                    'total': sum(stats.values())
                })
            
            time.sleep(15)  # Rate limiting pour free tier
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def enrich_domain(self, domain: str) -> Dict:
        """Enrichit un domaine via VirusTotal"""
        result = {
            'ioc': domain,
            'type': 'domain',
            'reputation': 'unknown',
            'sources': []
        }
        
        # Check si domaine légitime connu (pour éviter requêtes API inutiles)
        if self.is_legitimate_domain(domain):
            result['reputation'] = 'clean'
            result['sources'].append({
                'name': 'Known Good Domain',
                'malicious': 0,
                'total': 0
            })
            return result
        
        if not self.vt_api_key:
            return result
        
        try:
            url = f'https://www.virustotal.com/api/v3/domains/{domain}'
            headers = {'x-apikey': self.vt_api_key}
            
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                
                if malicious > 5:
                    result['reputation'] = 'malicious'
                elif malicious > 0:
                    result['reputation'] = 'suspicious'
                else:
                    result['reputation'] = 'clean'
                
                result['sources'].append({
                    'name': 'VirusTotal',
                    'malicious': malicious,
                    'total': sum(stats.values())
                })
            
            time.sleep(15)  # Rate limiting
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def enrich_url(self, url: str) -> Dict:
        """Enrichit une URL via VirusTotal"""
        result = {
            'ioc': url,
            'type': 'url',
            'reputation': 'unknown',
            'sources': []
        }
        
        if not self.vt_api_key:
            return result
        
        try:
            # Encoder l'URL en base64 (sans padding)
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            api_url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
            headers = {'x-apikey': self.vt_api_key}
            
            response = self.session.get(api_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                
                if malicious > 5:
                    result['reputation'] = 'malicious'
                elif malicious > 0:
                    result['reputation'] = 'suspicious'
                else:
                    result['reputation'] = 'clean'
                
                result['sources'].append({
                    'name': 'VirusTotal',
                    'malicious': malicious,
                    'total': sum(stats.values())
                })
            
            time.sleep(15)  # Rate limiting
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def enrich_email(self, email: str) -> Dict:
        """Enrichit un email en analysant son domaine"""
        result = {
            'ioc': email,
            'type': 'email',
            'reputation': 'unknown',
            'sources': []
        }
        
        # Pas d'API publique pour les emails, on analyse le domaine
        try:
            domain = email.split('@')[1]
            
            # Analyser le domaine via VirusTotal
            domain_result = self.enrich_domain(domain)
            
            # Si le domaine est malveillant, l'email est malveillant
            if domain_result['reputation'] == 'malicious':
                result['reputation'] = 'malicious'
                result['sources'].append({
                    'name': 'Domain Analysis',
                    'detail': f"Email domain '{domain}' is malicious",
                    'malicious': domain_result['sources'][0].get('malicious', 0) if domain_result['sources'] else 0
                })
            elif domain_result['reputation'] == 'suspicious':
                result['reputation'] = 'suspicious'
                result['sources'].append({
                    'name': 'Domain Analysis',
                    'detail': f"Email domain '{domain}' is suspicious",
                    'malicious': domain_result['sources'][0].get('malicious', 0) if domain_result['sources'] else 0
                })
            # Sinon reste unknown
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def enrich_all(self, iocs: Dict[str, Set[str]]) -> List[Dict]:
        """Enrichit tous les IOCs extraits"""
        enriched = []
        
        # Enrichissement des IPs
        if 'ipv4' in iocs:
            for ip in iocs['ipv4']:
                enriched.append(self.enrich_ip(ip))
        
        # Enrichissement des hashes
        for hash_type in ['md5', 'sha1', 'sha256']:
            if hash_type in iocs:
                for hash_val in iocs[hash_type]:
                    enriched.append(self.enrich_hash(hash_val))
        
        # Enrichissement des domaines (DYNAMIQUE via VirusTotal)
        if 'domain' in iocs:
            for domain in iocs['domain']:
                enriched.append(self.enrich_domain(domain))
        
        # Enrichissement des URLs (via VirusTotal)
        if 'url' in iocs:
            for url in iocs['url']:
                enriched.append(self.enrich_url(url))
        
        # Enrichissement des emails (via analyse du domaine)
        if 'email' in iocs:
            for email in iocs['email']:
                enriched.append(self.enrich_email(email))
        
        return enriched


class ReportGenerator:
    """Génère des rapports d'analyse"""
    
    @staticmethod
    def generate_json(enriched_iocs: List[Dict], output_file: str):
        """Génère un rapport JSON"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_iocs': len(enriched_iocs),
            'summary': {
                'malicious': sum(1 for i in enriched_iocs if i['reputation'] == 'malicious'),
                'suspicious': sum(1 for i in enriched_iocs if i['reputation'] == 'suspicious'),
                'clean': sum(1 for i in enriched_iocs if i['reputation'] == 'clean'),
                'unknown': sum(1 for i in enriched_iocs if i['reputation'] == 'unknown')
            },
            'iocs': enriched_iocs
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return report
    
    @staticmethod
    def generate_html(enriched_iocs: List[Dict], output_file: str):
        """Génère un rapport HTML"""
        summary = {
            'malicious': sum(1 for i in enriched_iocs if i['reputation'] == 'malicious'),
            'suspicious': sum(1 for i in enriched_iocs if i['reputation'] == 'suspicious'),
            'clean': sum(1 for i in enriched_iocs if i['reputation'] == 'clean'),
            'unknown': sum(1 for i in enriched_iocs if i['reputation'] == 'unknown')
        }
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>IOC Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 20px 0; }}
        .stat-box {{ padding: 15px; border-radius: 5px; text-align: center; }}
        .malicious {{ background-color: #e74c3c; color: white; }}
        .suspicious {{ background-color: #f39c12; color: white; }}
        .clean {{ background-color: #27ae60; color: white; }}
        .unknown {{ background-color: #95a5a6; color: white; }}
        .stat-number {{ font-size: 32px; font-weight: bold; }}
        .stat-label {{ font-size: 14px; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th {{ background-color: #34495e; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px; border-bottom: 1px solid #ddd; }}
        tr:hover {{ background-color: #f5f5f5; }}
        .badge {{ padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }}
        .badge-malicious {{ background-color: #e74c3c; color: white; }}
        .badge-suspicious {{ background-color: #f39c12; color: white; }}
        .badge-clean {{ background-color: #27ae60; color: white; }}
        .badge-unknown {{ background-color: #95a5a6; color: white; }}
        .timestamp {{ color: #7f8c8d; font-size: 14px; margin-top: 10px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 IOC Analysis Report</h1>
        <div class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        
        <div class="summary">
            <div class="stat-box malicious">
                <div class="stat-number">{summary['malicious']}</div>
                <div class="stat-label">Malicious</div>
            </div>
            <div class="stat-box suspicious">
                <div class="stat-number">{summary['suspicious']}</div>
                <div class="stat-label">Suspicious</div>
            </div>
            <div class="stat-box clean">
                <div class="stat-number">{summary['clean']}</div>
                <div class="stat-label">Clean</div>
            </div>
            <div class="stat-box unknown">
                <div class="stat-number">{summary['unknown']}</div>
                <div class="stat-label">Unknown</div>
            </div>
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>IOC</th>
                    <th>Type</th>
                    <th>Reputation</th>
                    <th>Sources</th>
                </tr>
            </thead>
            <tbody>
"""
        
        for ioc in enriched_iocs:
            reputation_class = f"badge-{ioc['reputation']}"
            sources_text = ', '.join([s['name'] for s in ioc['sources']]) if ioc['sources'] else 'N/A'
            
            html += f"""
                <tr>
                    <td><code>{ioc['ioc']}</code></td>
                    <td>{ioc['type'].upper()}</td>
                    <td><span class="badge {reputation_class}">{ioc['reputation'].upper()}</span></td>
                    <td>{sources_text}</td>
                </tr>
"""
        
        html += """
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)


def main():
    parser = argparse.ArgumentParser(
        description='IOC Analyzer - Extraction et enrichissement d\'IOCs',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  %(prog)s -i threat_report.txt
  %(prog)s -i alert.txt --vt YOUR_VT_KEY --abuse YOUR_ABUSE_KEY
  %(prog)s -t "Suspicious IP: 1.2.3.4 and hash: d41d8cd98f00b204e9800998ecf8427e"
        """
    )
    
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-i', '--input', help='Fichier d\'entrée contenant le texte à analyser')
    input_group.add_argument('-t', '--text', help='Texte à analyser directement')
    
    parser.add_argument('--vt', default=DEFAULT_VT_KEY, help='Clé API VirusTotal (optionnel, ou depuis config/config.py)')
    parser.add_argument('--abuse', default=DEFAULT_ABUSE_KEY, help='Clé API AbuseIPDB (optionnel, ou depuis config/config.py)')
    parser.add_argument('-o', '--output', default='ioc_report', help='Nom de base pour les fichiers de sortie')
    parser.add_argument('--no-enrich', action='store_true', help='Désactiver l\'enrichissement (extraction uniquement)')
    
    args = parser.parse_args()
    
    # Lecture du texte d'entrée
    if args.input:
        try:
            with open(args.input, 'r', encoding='utf-8') as f:
                text = f.read()
        except FileNotFoundError:
            print(f"[!] Erreur: Fichier '{args.input}' introuvable")
            return
        
        # Générer nom automatique basé sur fichier d'entrée
        if args.output == 'ioc_report':  # Valeur par défaut
            input_name = Path(args.input).stem  # Nom sans extension
            output_name = f"analyse_{input_name}"
        else:
            output_name = args.output
    else:
        text = args.text
        output_name = args.output
    
    # Créer dossier outputs/ s'il n'existe pas
    output_dir = Path('outputs')
    output_dir.mkdir(exist_ok=True)
    
    print("[*] Extraction des IOCs en cours...")
    extractor = IOCExtractor()
    iocs = extractor.extract(text)
    
    total_iocs = sum(len(v) for v in iocs.values())
    print(f"[+] {total_iocs} IOCs extraits:")
    for ioc_type, values in iocs.items():
        print(f"    - {ioc_type.upper()}: {len(values)}")
    
    # Enrichissement
    if not args.no_enrich:
        print("\n[*] Enrichissement des IOCs...")
        enricher = IOCEnricher(vt_api_key=args.vt, abuseipdb_key=args.abuse)
        enriched_iocs = enricher.enrich_all(iocs)
    else:
        print("\n[!] Enrichissement désactivé")
        enriched_iocs = []
        for ioc_type, values in iocs.items():
            for ioc in values:
                enriched_iocs.append({
                    'ioc': ioc,
                    'type': ioc_type,
                    'reputation': 'unknown',
                    'sources': []
                })
    
    # Génération des rapports dans outputs/
    print("\n[*] Génération des rapports...")
    report_gen = ReportGenerator()
    
    json_file = output_dir / f"{output_name}.json"
    html_file = output_dir / f"{output_name}.html"
    
    report_gen.generate_json(enriched_iocs, str(json_file))
    report_gen.generate_html(enriched_iocs, str(html_file))
    
    print(f"[+] Rapport JSON: {json_file}")
    print(f"[+] Rapport HTML: {html_file}")
    print("\n[✓] Analyse terminée!")
    
    # Ouvrir automatiquement le rapport HTML
    print(f"\n[*] Ouverture du rapport HTML...")
    webbrowser.open(str(html_file.absolute()))



if __name__ == '__main__':
    main()