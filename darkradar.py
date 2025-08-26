import click
import json
import hashlib
import re
import requests
from datetime import datetime
import yaml


# === ENHANCED DETECTION RULES ===
class DetectionRules:
    def __init__(self, config_file=None):
        if config_file:
            self.load_from_config(config_file)
        else:
            self.load_default_rules()

    def load_default_rules(self):
        # Multi-layer Keywords
        self.KEYWORDS = {
            "military": ["tni", "polri", "kopassus", "kostrad", "marinir", "paskhas", "brimob"],
            "operations": ["ops", "operasi", "latihan", "misi", "sandi", "intel", "komando"],
            "ranks": ["jenderal", "kolonel", "mayor", "kapten", "letnan", "sersan", "kopral"],
            "units": ["satuan", "batalyon", "kompi", "detasemen", "skadron", "armada", "pangkalan"],
            "weapons": ["senpi", "senjata", "amunisi", "rudal", "tank", "pesawat", "kapal"],
            "locations": ["mabes", "kodam", "kodim", "lanud", "lanal", "pangkalan", "markas"],
            "documents": ["rahasia", "terbatas", "classified", "confidential", "internal", "briefing"]
        }

        # Email Patterns (Multi-domain)
        self.EMAIL_PATTERNS = [
            r"[a-zA-Z0-9._%+-]+@tni\.mil\.id",
            r"[a-zA-Z0-9._%+-]+@polri\.go\.id",
            r"[a-zA-Z0-9._%+-]+@kemhan\.go\.id",
            r"[a-zA-Z0-9._%+-]+@tnial\.mil\.id",
            r"[a-zA-Z0-9._%+-]+@tniau\.mil\.id",
            r"[a-zA-Z0-9._%+-]+@tniad\.mil\.id"
        ]

        # Phone Patterns
        self.PHONE_PATTERNS = [
            r"\b08\d{8,11}\b",  # Indonesian mobile
            r"\b\+62\s?8\d{8,11}\b",  # Indonesian mobile with country code
            r"\b021-\d{7,8}\b",  # Jakarta landline
            r"\b\d{3,4}-\d{6,8}\b"  # General landline pattern
        ]

        # ID Numbers
        self.ID_PATTERNS = [
            r"\b\d{16}\b",  # NIK (Indonesian ID)
            r"\b\d{10}\b",  # NRP (Military ID)
            r"NRP\s*[:\-]?\s*\d{8,12}",  # NRP with label
            r"NIK\s*[:\-]?\s*\d{16}"  # NIK with label
        ]

        # Coordinates
        self.COORDINATE_PATTERNS = [
            r"-?\d{1,3}\.\d+,\s*-?\d{1,3}\.\d+",  # Lat,Long
            r"\d{1,2}°\d{1,2}'\d{1,2}\.\d+\"[NS]\s+\d{1,3}°\d{1,2}'\d{1,2}\.\d+\"[EW]"  # DMS format
        ]

        # URLs and Domains
        self.URL_PATTERNS = [
            r"https?://[a-zA-Z0-9.-]+\.mil\.id[/\w\-._~:/?#[\]@!$&'()*+,;=%]*",
            r"https?://[a-zA-Z0-9.-]+\.go\.id[/\w\-._~:/?#[\]@!$&'()*+,;=%]*",
            r"\b[a-zA-Z0-9.-]+\.mil\.id\b",
            r"\b[a-zA-Z0-9.-]+\.go\.id\b"
        ]

    def load_from_config(self, config_file):
        """Load rules from YAML config file"""
        with open(config_file, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
            self.KEYWORDS = config.get('keywords', {})
            self.EMAIL_PATTERNS = config.get('email_patterns', [])
            self.PHONE_PATTERNS = config.get('phone_patterns', [])
            self.ID_PATTERNS = config.get('id_patterns', [])
            self.COORDINATE_PATTERNS = config.get('coordinate_patterns', [])
            self.URL_PATTERNS = config.get('url_patterns', [])


# === ENHANCED SCANNER ===
class EnhancedScanner:
    def __init__(self, rules):
        self.rules = rules

    def scan_text(self, text):
        """Comprehensive text scanning with detailed scoring"""
        findings = {
            "total_score": 0,
            "matches": {},
            "risk_level": "LOW"
        }

        text_lower = text.lower()

        # 1. Keyword Analysis
        keyword_matches = {}
        for category, keywords in self.rules.KEYWORDS.items():
            matches = [kw for kw in keywords if kw in text_lower]
            if matches:
                keyword_matches[category] = matches
                # Progressive scoring: more categories = higher risk
                findings["total_score"] += len(matches) * 15 + len(keyword_matches) * 10

        if keyword_matches:
            findings["matches"]["keywords"] = keyword_matches

        # 2. Email Detection
        email_matches = []
        for pattern in self.rules.EMAIL_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            email_matches.extend(matches)

        if email_matches:
            findings["matches"]["emails"] = list(set(email_matches))
            findings["total_score"] += len(set(email_matches)) * 80

        # 3. Phone Number Detection
        phone_matches = []
        for pattern in self.rules.PHONE_PATTERNS:
            matches = re.findall(pattern, text)
            phone_matches.extend(matches)

        if phone_matches:
            findings["matches"]["phones"] = list(set(phone_matches))
            findings["total_score"] += len(set(phone_matches)) * 30

        # 4. ID Number Detection
        id_matches = []
        for pattern in self.rules.ID_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            id_matches.extend(matches)

        if id_matches:
            findings["matches"]["ids"] = list(set(id_matches))
            findings["total_score"] += len(set(id_matches)) * 60

        # 5. Coordinate Detection
        coord_matches = []
        for pattern in self.rules.COORDINATE_PATTERNS:
            matches = re.findall(pattern, text)
            coord_matches.extend(matches)

        if coord_matches:
            findings["matches"]["coordinates"] = list(set(coord_matches))
            findings["total_score"] += len(set(coord_matches)) * 70

        # 6. URL/Domain Detection
        url_matches = []
        for pattern in self.rules.URL_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            url_matches.extend(matches)

        if url_matches:
            findings["matches"]["urls"] = list(set(url_matches))
            findings["total_score"] += len(set(url_matches)) * 40

        # Risk Level Assessment
        if findings["total_score"] >= 200:
            findings["risk_level"] = "CRITICAL"
        elif findings["total_score"] >= 100:
            findings["risk_level"] = "HIGH"
        elif findings["total_score"] >= 50:
            findings["risk_level"] = "MEDIUM"
        else:
            findings["risk_level"] = "LOW"

        return findings


# === MULTIPLE DATA SOURCES ===
class DataSources:
    @staticmethod
    def fetch_hibp_breaches(domain):
        """HaveIBeenPwned API"""
        url = "https://haveibeenpwned.com/api/v3/breaches"
        headers = {"User-Agent": "DarkRadar-Enhanced"}

        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except requests.RequestException as e:
            click.echo(f"[ERROR] HIBP API error: {e}")
        return []

    @staticmethod
    def fetch_pastebin_search(keywords):
        """Simulate Pastebin search (requires actual API implementation)"""
        # Placeholder for Pastebin API integration
        return []

    @staticmethod
    def fetch_github_search(keywords):
        """GitHub API search"""
        results = []
        for keyword in keywords[:3]:  # Limit to avoid rate limiting
            url = f"https://api.github.com/search/code?q={keyword}+extension:txt+extension:log"
            headers = {"User-Agent": "DarkRadar-Enhanced"}

            try:
                resp = requests.get(url, headers=headers, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get('items', [])[:5]:  # Limit results
                        results.append({
                            "source": "github",
                            "url": item.get('html_url'),
                            "text": f"Found in {item.get('name')}: {keyword}",
                            "detected_at": datetime.utcnow().isoformat()
                        })
            except requests.RequestException as e:
                click.echo(f"[WARNING] GitHub API error for '{keyword}': {e}")

        return results

    @staticmethod
    def fetch_social_media_mentions(keywords):
        """Placeholder for social media API integration"""
        # Would integrate with Twitter API, Reddit API, etc.
        return []


# === BANNER ===
def print_banner():
    banner = r"""
 _______                       __              _______                   __                            ________  __    __  ______ 
|       \                     |  \            |       \                 |  \                          |        \|  \  |  \|      \
| $$$$$$$\  ______    ______  | $$   __       | $$$$$$$\  ______    ____| $$  ______    ______         \$$$$$$$$| $$\ | $$ \$$$$$$
| $$  | $$ |      \  /      \ | $$  /  \      | $$__| $$ |      \  /      $$ |      \  /      \          | $$   | $$$\| $$  | $$  
| $$  | $$  \$$$$$$\|  $$$$$$\| $$_/  $$      | $$    $$  \$$$$$$\|  $$$$$$$  \$$$$$$\|  $$$$$$\         | $$   | $$$$\ $$  | $$  
| $$  | $$ /      $$| $$   \$$| $$   $$       | $$$$$$$\ /      $$| $$  | $$ /      $$| $$   \$$         | $$   | $$\$$ $$  | $$  
| $$__/ $$|  $$$$$$$| $$      | $$$$$$\       | $$  | $$|  $$$$$$$| $$__| $$|  $$$$$$$| $$               | $$   | $$ \$$$$ _| $$_ 
| $$    $$ \$$    $$| $$      | $$  \$$\      | $$  | $$ \$$    $$ \$$    $$ \$$    $$| $$               | $$   | $$  \$$$|   $$ \
 \$$$$$$$   \$$$$$$$ \$$       \$$   \$$       \$$   \$$  \$$$$$$$  \$$$$$$$  \$$$$$$$ \$$                \$$    \$$   \$$ \$$$$$$
                                                                                                                                                                                                                                                                                                                                                    
    Enhanced Multi-Source Intelligence Gathering & Threat Detection System
                                  Author : @YogaGymn
    """
    print(banner)


# === CLI COMMANDS ===
@click.group()
@click.option('--config', help='Path to YAML configuration file')
@click.pass_context
def cli(ctx, config):
    """Enhanced DarkRadar CLI - Advanced data leak monitoring."""
    ctx.ensure_object(dict)
    print_banner()
    ctx.obj['rules'] = DetectionRules(config)
    ctx.obj['scanner'] = EnhancedScanner(ctx.obj['rules'])


@cli.command()
@click.option('--sources', default='hibp,github', help='Data sources: hibp,github,pastebin,social')
@click.option('--keywords', help='Custom keywords (comma-separated)')
@click.option('--domain', help='Target domain')
@click.option('--output', default='enhanced_feed.json', help='Output file')
@click.pass_context
def fetch(ctx, sources, keywords, domain, output):
    """Fetch data from multiple sources."""
    results = []
    source_list = sources.split(',')

    # Get keywords from config or custom input
    all_keywords = []
    if keywords:
        all_keywords.extend(keywords.split(','))

    # Add keywords from config
    for category, kw_list in ctx.obj['rules'].KEYWORDS.items():
        all_keywords.extend(kw_list[:3])  # Limit per category

    click.echo(f"[INFO] Fetching from sources: {source_list}")
    click.echo(f"[INFO] Using keywords: {all_keywords[:10]}...")  # Show first 10

    if 'hibp' in source_list and domain:
        click.echo("[INFO] Fetching from HaveIBeenPwned...")
        hibp_data = DataSources.fetch_hibp_breaches(domain)
        for breach in hibp_data:
            if any(kw in str(breach).lower() for kw in all_keywords):
                results.append({
                    "source": "hibp",
                    "text": f"Domain {domain} found in breach: {breach.get('Name', 'Unknown')}",
                    "detected_at": datetime.utcnow().isoformat(),
                    "metadata": breach
                })

    if 'github' in source_list:
        click.echo("[INFO] Searching GitHub...")
        github_results = DataSources.fetch_github_search(all_keywords[:5])
        results.extend(github_results)

    # Save results
    with open(output, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    click.echo(f"[OK] Enhanced feed saved to {output}, total {len(results)} items.")


@cli.command()
@click.option('--input', '-i', required=True, help='Feed JSON input')
@click.option('--output', '-o', default='enhanced_results.json', help='Results output')
@click.option('--threshold', default=50, help='Minimum risk score threshold')
@click.pass_context
def scan(ctx, input, output, threshold):
    """Enhanced scanning with multi-layer detection."""
    with open(input, 'r', encoding='utf-8') as f:
        data = json.load(f)

    scanner = ctx.obj['scanner']
    findings = []

    click.echo(f"[INFO] Scanning {len(data)} entries with threshold {threshold}...")

    for entry in data:
        text = entry.get("text", "")
        if not text:
            continue

        scan_result = scanner.scan_text(text)

        if scan_result["total_score"] >= threshold:
            finding = {
                "id": hashlib.sha256(text.encode()).hexdigest()[:16],
                "source": entry.get("source", "unknown"),
                "risk_score": scan_result["total_score"],
                "risk_level": scan_result["risk_level"],
                "matches": scan_result["matches"],
                "excerpt": text[:300] + "..." if len(text) > 300 else text,
                "detected_at": entry.get("detected_at", datetime.utcnow().isoformat()),
                "metadata": entry.get("metadata", {})
            }
            findings.append(finding)

    # Sort by risk score (highest first)
    findings.sort(key=lambda x: x["risk_score"], reverse=True)

    with open(output, 'w', encoding='utf-8') as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)

    click.echo(f"[OK] Enhanced scan complete! Found {len(findings)} high-risk items.")

    # Quick summary
    risk_summary = {}
    for finding in findings:
        level = finding["risk_level"]
        risk_summary[level] = risk_summary.get(level, 0) + 1

    click.echo(f"[SUMMARY] Risk levels: {risk_summary}")


@cli.command()
@click.option('--input', '-i', required=True, help='Scan results file')
@click.option('--format', default='detailed', help='Output format: detailed, summary, json')
@click.option('--risk-level', help='Filter by risk level: LOW, MEDIUM, HIGH, CRITICAL')
def analyze(input, format, risk_level):
    """Analyze enhanced scan results."""
    with open(input, 'r', encoding='utf-8') as f:
        findings = json.load(f)

    if risk_level:
        findings = [f for f in findings if f["risk_level"] == risk_level.upper()]

    if format == 'summary':
        click.echo(f"\n=== ANALYSIS SUMMARY ===")
        click.echo(f"Total findings: {len(findings)}")

        # Risk level breakdown
        risk_counts = {}
        for f in findings:
            level = f["risk_level"]
            risk_counts[level] = risk_counts.get(level, 0) + 1

        for level, count in sorted(risk_counts.items()):
            click.echo(f"{level}: {count}")

        # Top sources
        source_counts = {}
        for f in findings:
            source = f["source"]
            source_counts[source] = source_counts.get(source, 0) + 1

        click.echo(f"\nTop Sources:")
        for source, count in sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            click.echo(f"  {source}: {count}")

    elif format == 'detailed':
        for finding in findings:
            click.echo(f"\n{'=' * 60}")
            click.echo(f"🚨 RISK: {finding['risk_level']} (Score: {finding['risk_score']})")
            click.echo(f"📍 Source: {finding['source']}")
            click.echo(f"🕐 Detected: {finding['detected_at']}")
            click.echo(f"🆔 ID: {finding['id']}")

            if finding.get('matches'):
                click.echo(f"🔍 Matches:")
                for match_type, matches in finding['matches'].items():
                    if isinstance(matches, dict):
                        for category, items in matches.items():
                            click.echo(f"   {match_type}.{category}: {items}")
                    else:
                        click.echo(f"   {match_type}: {matches}")

            click.echo(f"📄 Excerpt: {finding['excerpt']}")

    elif format == 'json':
        click.echo(json.dumps(findings, indent=2, ensure_ascii=False))


@cli.command()
@click.option('--input', '-i', required=True, help='Scan results file')
@click.option('--webhook', help='Slack webhook URL')
@click.option('--email-to', help='Email recipient')
@click.option('--min-risk', default='HIGH', help='Minimum risk level for alerts')
def alert(input, webhook, email_to, min_risk):
    """Send enhanced alerts."""
    with open(input, 'r', encoding='utf-8') as f:
        findings = json.load(f)

    # Filter by risk level
    risk_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    min_index = risk_order.index(min_risk)

    alert_findings = [
        f for f in findings
        if risk_order.index(f['risk_level']) >= min_index
    ]

    if not alert_findings:
        click.echo("[INFO] No findings meet alert criteria.")
        return

    for finding in alert_findings:
        emoji = "🔴" if finding['risk_level'] == 'CRITICAL' else "🟡"
        msg = f"{emoji} [{finding['risk_level']}] Score: {finding['risk_score']} | Source: {finding['source']}"
        click.echo(f"[ALERT] {msg}")

        # Show key matches
        if finding.get('matches'):
            for match_type, matches in list(finding['matches'].items())[:2]:  # Limit output
                if isinstance(matches, dict):
                    for category, items in list(matches.items())[:2]:
                        click.echo(f"   Found {match_type}.{category}: {items[:3]}")
                else:
                    click.echo(f"   Found {match_type}: {matches[:3]}")


# Generate sample config
@cli.command()
@click.option('--output', default='darkradar_config.yaml', help='Config file output')
def generate_config(output):
    """Generate sample configuration file."""
    config = {
        'keywords': {
            'military': ['tni', 'polri', 'tentara'],
            'operations': ['operasi', 'latihan', 'misi'],
            'sensitive': ['rahasia', 'classified', 'confidential']
        },
        'email_patterns': [
            r'[a-zA-Z0-9._%+-]+@tni\.mil\.id',
            r'[a-zA-Z0-9._%+-]+@polri\.go\.id'
        ],
        'phone_patterns': [
            r'\b08\d{8,11}\b',
            r'\+62\s?8\d{8,11}'
        ],
        'id_patterns': [
            r'\b\d{16}\b',
            r'NRP\s*[:\-]?\s*\d{8,12}'
        ]
    }

    with open(output, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, default_flow_style=False, allow_unicode=True)

    click.echo(f"[OK] Sample config generated: {output}")


if __name__ == "__main__":
    cli()