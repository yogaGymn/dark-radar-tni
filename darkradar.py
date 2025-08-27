#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import click
import json
import hashlib
import re
import requests
from datetime import datetime
import yaml
from bs4 import BeautifulSoup
import time
from urllib.parse import urljoin, urlparse
import urllib3

# ====== Network warnings (karena verify=False) ======
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT = "DarkRadar-TNI/1.0 (+security monitoring)"
REQ_TIMEOUT = 15


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
            "locations": ["mabes", "kodam", "kodim", "lanud", "lanal", "pangkalan", "markas", "jakarta", "cilangkap"],
            "documents": ["rahasia", "terbatas", "classified", "confidential", "internal", "briefing"]
        }

        # Email Patterns (Multi-domain)
        self.EMAIL_PATTERNS = [
            r"[a-zA-Z0-9._%+-]+@tni\.mil\.id",
            r"[a-zA-Z0-9._%+-]+@polri\.go\.id",
            r"[a-zA-Z0-9._%+-]+@kemhan\.go\.id",
            r"[a-zA-Z0-9._%+-]+@tnial\.mil\.id",
            r"[a-zA-Z0-9._%+-]+@tniau\.mil\.id",
            r"[a-zA-Z0-9._%+-]+@tniad\.mil\.id",
        ]

        # Phone Patterns
        self.PHONE_PATTERNS = [
            r"\b08\d{8,11}\b",            # Indonesian mobile
            r"\b\+62\s?8\d{8,11}\b",      # Indonesian mobile with country code
            r"\b021-\d{7,8}\b",           # Jakarta landline
            r"\b\d{3,4}-\d{6,8}\b"        # General landline pattern
        ]

        # ID Numbers
        self.ID_PATTERNS = [
            r"\b\d{16}\b",                        # NIK (Indonesian ID)
            r"\b\d{10}\b",                        # generic 10 digits (potensi NRP, hati-hati false positive)
            r"NRP\s*[:\-]?\s*\d{8,12}",           # NRP with label
            r"NIK\s*[:\-]?\s*\d{16}",             # NIK with label
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


# === SENSITIVE DATA PATTERNS (khusus) ===
SENSITIVE_PATTERNS = {
    "NIK": r"\b\d{16}\b",
    "Email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "Phone": r"\b(?:\+62\s?8\d{8,11}|08\d{8,11})\b",
    "IP Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "Credit Card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b",  # Visa/Master (basic)
    "Password": r"(?i)\b(password|pass|pwd)\b\s*[:=]\s*([^\s'\";]{4,})",
    "API Key/Token": r"(?i)\b(api[_-]?key|secret|token|bearer)\b\s*[:=]\s*([A-Za-z0-9\-\._]{8,})",
    "NRP": r"\b(?:NRP\s*[:\-]?\s*)?\d{8,12}\b",
    "Coordinates": r"-?\d{1,3}\.\d+,\s*-?\d{1,3}\.\d+",
}

SENSITIVE_WEIGHTS = {
    "NIK": 120,
    "Email": 40,          # email publik tidak selalu bocor
    "Phone": 60,
    "IP Address": 40,
    "Credit Card": 200,
    "Password": 220,
    "API Key/Token": 200,
    "NRP": 120,
    "Coordinates": 70,
}


def detect_sensitive_data(text):
    """Kembalikan temuan data sensitif + skor tambahan."""
    findings = {}
    extra_score = 0
    for label, pattern in SENSITIVE_PATTERNS.items():
        try:
            matches = re.findall(pattern, text)
        except re.error:
            matches = []
        # flatten tuple matches (untuk grup)
        flat = []
        for m in matches:
            if isinstance(m, tuple):
                flat.append("".join(m))
            else:
                flat.append(m)
        if flat:
            unique = list(dict.fromkeys(flat))[:10]  # limit contoh
            findings[label] = unique
            extra_score += SENSITIVE_WEIGHTS.get(label, 50) * min(len(unique), 2)  # batasi multiplier
    return findings, extra_score


# === ENHANCED SCANNER ===
class EnhancedScanner:
    def __init__(self, rules):
        self.rules = rules

    def scan_text(self, text):
        """Comprehensive text scanning dengan skor & risiko."""
        findings = {
            "total_score": 0,
            "matches": {},
            "risk_level": "LOW"
        }

        text_lower = text.lower()

        # 1) Keyword Analysis
        keyword_matches = {}
        for category, keywords in self.rules.KEYWORDS.items():
            matches = [kw for kw in keywords if kw in text_lower]
            if matches:
                keyword_matches[category] = matches
                findings["total_score"] += len(matches) * 12 + len(keyword_matches) * 8

        if keyword_matches:
            findings["matches"]["keywords"] = keyword_matches

        # 2) Email Detection (domain khusus)
        email_matches = []
        for pattern in self.rules.EMAIL_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            email_matches.extend(matches)
        if email_matches:
            findings["matches"]["emails_domain"] = list(dict.fromkeys(email_matches))[:10]
            findings["total_score"] += len(set(email_matches)) * 60

        # 3) Phone
        phone_matches = []
        for pattern in self.rules.PHONE_PATTERNS:
            matches = re.findall(pattern, text)
            phone_matches.extend(matches)
        if phone_matches:
            findings["matches"]["phones"] = list(dict.fromkeys(phone_matches))[:10]
            findings["total_score"] += len(set(phone_matches)) * 30

        # 4) IDs
        id_matches = []
        for pattern in self.rules.ID_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            id_matches.extend(matches)
        if id_matches:
            findings["matches"]["ids"] = list(dict.fromkeys(id_matches))[:10]
            findings["total_score"] += len(set(id_matches)) * 60

        # 5) Coordinates
        coord_matches = []
        for pattern in self.rules.COORDINATE_PATTERNS:
            matches = re.findall(pattern, text)
            coord_matches.extend(matches)
        if coord_matches:
            findings["matches"]["coordinates"] = list(dict.fromkeys(coord_matches))[:10]
            findings["total_score"] += len(set(coord_matches)) * 50

        # 6) URLs (extract cepat)
        url_matches = re.findall(r"https?://[^\s\"'>)]+", text)
        if url_matches:
            findings["matches"]["urls"] = list(dict.fromkeys(url_matches))[:20]
            findings["total_score"] += min(len(url_matches), 10) * 5

        # 7) Sensitive Data (khusus)
        sensitive_hits, extra = detect_sensitive_data(text)
        if sensitive_hits:
            findings["matches"]["sensitive"] = sensitive_hits
            findings["total_score"] += extra

        # Risk Level
        score = findings["total_score"]
        if score >= 280:
            findings["risk_level"] = "CRITICAL"
        elif score >= 160:
            findings["risk_level"] = "HIGH"
        elif score >= 80:
            findings["risk_level"] = "MEDIUM"
        else:
            findings["risk_level"] = "LOW"

        return findings


# === MULTIPLE DATA SOURCES (tetap dipertahankan) ===
class DataSources:
    @staticmethod
    def fetch_hibp_breaches(domain):
        """HaveIBeenPwned API (placeholder umum)"""
        url = "https://haveibeenpwned.com/api/v3/breaches"
        headers = {"User-Agent": USER_AGENT}
        try:
            resp = requests.get(url, headers=headers, timeout=REQ_TIMEOUT)
            if resp.status_code == 200:
                return resp.json()
        except requests.RequestException as e:
            click.echo(f"[ERROR] HIBP API error: {e}")
        return []

    @staticmethod
    def fetch_pastebin_search(keywords):
        return []

    @staticmethod
    def fetch_github_search(keywords):
        results = []
        for keyword in keywords[:3]:
            url = f"https://api.github.com/search/code?q={keyword}+extension:txt+extension:log"
            headers = {"User-Agent": USER_AGENT}
            try:
                resp = requests.get(url, headers=headers, timeout=REQ_TIMEOUT)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get('items', [])[:5]:
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


# ===== Helper: HTTP fetch & parsing =====
def fetch_page(url: str):
    headers = {"User-Agent": USER_AGENT}
    try:
        resp = requests.get(url, headers=headers, timeout=REQ_TIMEOUT, verify=False)
        return resp.status_code, resp.text
    except requests.RequestException as e:
        return None, str(e)


def extract_text_and_links(base_url: str, html: str):
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ", strip=True) if html else ""
    links = []
    for a in soup.find_all("a", href=True):
        full = urljoin(base_url, a["href"])
        links.append(full)
    # deduplicate links, prioritize same-domain
    seen = []
    for l in links:
        if l not in seen:
            seen.append(l)
    return text, seen


def print_alert(url: str, scan: dict):
    """Output rapi & mudah dianalisis."""
    line = "=" * 90
    print(line)
    print(f"[SCAN RESULT] {url}")
    print(f"  Risk: {scan.get('risk_level')}  |  Score: {scan.get('total_score')}")
    matches = scan.get("matches", {})

    # Sensitive first
    sensitive = matches.get("sensitive", {})
    if sensitive:
        print("  [SENSITIVE DATA] ⚠️  Detected")
        for label, vals in sensitive.items():
            show = ", ".join(vals[:5])
            print(f"    - {label}: {show}")

    # Keywords
    if "keywords" in matches and matches["keywords"]:
        print("  [KEYWORDS]")
        for cat, words in matches["keywords"].items():
            print(f"    - {cat}: {', '.join(words)}")

    # Emails (domain rules)
    if "emails_domain" in matches and matches["emails_domain"]:
        print("  [EMAILS-DOMAIN]")
        for e in matches["emails_domain"][:10]:
            print(f"    - {e}")

    # IDs
    if "ids" in matches and matches["ids"]:
        print("  [ID MATCHES]")
        for i in matches["ids"][:10]:
            print(f"    - {i}")

    # Phones
    if "phones" in matches and matches["phones"]:
        print("  [PHONES]")
        for p in matches["phones"][:10]:
            print(f"    - {p}")

    # Coordinates
    if "coordinates" in matches and matches["coordinates"]:
        print("  [COORDINATES]")
        for c in matches["coordinates"][:10]:
            print(f"    - {c}")

    # URLs
    if "urls" in matches and matches["urls"]:
        print("  [URLS] (sample)")
        for u in matches["urls"][:10]:
            print(f"    - {u}")

    print(line + "\n")


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
    """Fetch data dari beberapa sumber (non-realtime)."""
    results = []
    source_list = sources.split(',')

    all_keywords = []
    if keywords:
        all_keywords.extend([k.strip() for k in keywords.split(',') if k.strip()])

    for category, kw_list in ctx.obj['rules'].KEYWORDS.items():
        all_keywords.extend(kw_list[:3])

    click.echo(f"[INFO] Fetching from sources: {source_list}")
    click.echo(f"[INFO] Using keywords: {all_keywords[:10]}...")

    if 'hibp' in source_list and domain:
        click.echo("[INFO] Fetching from HaveIBeenPwned...")
        hibp_data = DataSources.fetch_hibp_breaches(domain)
        for breach in hibp_data:
            if any(kw in json.dumps(breach).lower() for kw in all_keywords):
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

    with open(output, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    click.echo(f"[OK] Enhanced feed saved to {output}, total {len(results)} items.")


@cli.command()
@click.option('--input', '-i', required=True, help='Feed JSON input')
@click.option('--output', '-o', default='enhanced_results.json', help='Results output')
@click.option('--threshold', default=80, help='Minimum risk score threshold')
@click.pass_context
def scan(ctx, input, output, threshold):
    """Scan data dari feed JSON (offline)."""
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

    findings.sort(key=lambda x: x["risk_score"], reverse=True)

    with open(output, 'w', encoding='utf-8') as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)

    click.echo(f"[OK] Scan complete! Found {len(findings)} items >= threshold {threshold}.")

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
    """Analisis hasil scan (offline)."""
    with open(input, 'r', encoding='utf-8') as f:
        findings = json.load(f)

    if risk_level:
        findings = [f for f in findings if f["risk_level"] == risk_level.upper()]

    if format == 'summary':
        click.echo(f"\n=== ANALYSIS SUMMARY ===")
        click.echo(f"Total findings: {len(findings)}")

        risk_counts = {}
        for f in findings:
            level = f["risk_level"]
            risk_counts[level] = risk_counts.get(level, 0) + 1

        for level, count in sorted(risk_counts.items()):
            click.echo(f"{level}: {count}")

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
    """Kirim notifikasi alert (placeholder)."""
    with open(input, 'r', encoding='utf-8') as f:
        findings = json.load(f)

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


# === REALTIME CRAWLER TNI ===
@cli.command()
@click.option('--interval', default=60, show_default=True, help='Interval fetch (detik)')
@click.pass_context
def realtime(ctx, interval):
    """
    Realtime monitoring untuk tni.mil.id dan subdomain-subdomain.
    Output: deteksi kata kunci + data sensitif + URL sumber.
    """
    scanner = ctx.obj['scanner']

    target_urls = [
        "https://tni.mil.id",
        "https://www.tni.mil.id",
        "https://webmail.mil.id",
        "https://webdisk.mil.id",
        "https://puspen.mil.id",
        "https://nms.mil.id",
        "https://mx2.mil.id",
        "https://mediaanalisis.mil.id",
        "https://main-mx.mil.id",
        "https://jdih.mil.id",
    ]

    click.echo(f"[INFO] Realtime monitoring start: {len(target_urls)} root targets ...\n")

    visited_recent = {}  # simple cooldown untuk URL (hindari spam)
    cooldown_sec = max(30, interval // 2)

    while True:
        cycle_start = datetime.utcnow().isoformat()
        click.echo(f"[INFO] New cycle @ {cycle_start} (interval={interval}s)")
        for base_url in target_urls:
            status, html = fetch_page(base_url)
            if status is None:
                click.echo(f"[ERROR] {base_url} -> {html}")
                continue
            if status != 200:
                click.echo(f"[WARNING] {base_url} status {status}")
                continue

            # halaman utama
            text, links = extract_text_and_links(base_url, html)
            scan = scanner.scan_text(text)
            if scan["total_score"] > 0:
                print_alert(base_url, scan)

            # scan link internal (1 hop, same registrable domain .mil.id)
            for link in links[:50]:  # batasi supaya ringan
                try:
                    parsed = urlparse(link)
                    if not parsed.scheme.startswith("http"):
                        continue
                    if ".mil.id" not in parsed.netloc:
                        continue

                    # cooldown per URL
                    now_ts = time.time()
                    last = visited_recent.get(link, 0)
                    if now_ts - last < cooldown_sec:
                        continue
                    visited_recent[link] = now_ts

                    s, h = fetch_page(link)
                    if s != 200 or not h:
                        continue
                    t, _ = extract_text_and_links(link, h)
                    sub_scan = scanner.scan_text(t)
                    if sub_scan["total_score"] > 0:
                        print_alert(link, sub_scan)

                except Exception as e:
                    click.echo(f"[ERROR] fetch {link}: {e}")

        click.echo(f"[INFO] Sleeping {interval} detik...\n")
        time.sleep(interval)


if __name__ == "__main__":
    cli()
