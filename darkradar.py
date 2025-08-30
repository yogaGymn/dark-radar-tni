#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import requests
import click
from datetime import datetime

# ========== BANNER ==========
BANNER = r"""
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

# ========== TOR UTILS ==========
class TorUtils:
    TOR_PROXY = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }

    @staticmethod
    def is_tor_running():
        try:
            resp = requests.get(
                "https://check.torproject.org/api/ip",
                proxies=TorUtils.TOR_PROXY,
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                return data.get("IsTor", False)
            return False
        except Exception:
            return False


# ========== INTERNET SOURCES ==========
class DataSources:
    @staticmethod
    def fetch_github_search(keywords):
        results = []
        for keyword in keywords:
            url = f"https://api.github.com/search/code?q={keyword}"
            try:
                resp = requests.get(url, timeout=20)
                if resp.status_code == 200:
                    results.append({
                        "source": "internet/github",
                        "url": url,
                        "text": f"Hasil pencarian GitHub untuk: {keyword}",
                        "detected_at": datetime.utcnow().isoformat()
                    })
            except Exception as e:
                results.append({
                    "source": "internet/github",
                    "error": str(e),
                    "keyword": keyword
                })
        return results


# ========== DARKWEB SOURCES ==========
class DarkwebSources:
    TOR_PROXY = TorUtils.TOR_PROXY

    @staticmethod
    def search_darkweb(keywords):
        results = []
        for keyword in keywords:
            url = f"https://ahmia.fi/search/?q={keyword}"
            try:
                resp = requests.get(url, proxies=DarkwebSources.TOR_PROXY, timeout=30)
                if resp.status_code == 200:
                    results.append({
                        "source": "darkweb/ahmia",
                        "url": url,
                        "text": f"Hasil pencarian di Ahmia untuk: {keyword}",
                        "detected_at": datetime.utcnow().isoformat()
                    })
            except Exception as e:
                results.append({
                    "source": "darkweb/ahmia",
                    "error": str(e),
                    "keyword": keyword
                })
        return results


# ========== HELPER OUTPUT ==========
def print_results(results):
    """Cetak hasil pencarian dengan format tabel rapi"""
    if not results:
        click.echo("   [!] Tidak ada hasil.")
        return

    for i, r in enumerate(results, 1):
        click.echo(f"\n[{i}] Source : {r.get('source')}")
        if "error" in r:
            click.echo(f"    ❌ Error : {r['error']}")
        else:
            click.echo(f"    ✅ URL   : {r.get('url')}")
            click.echo(f"    Info    : {r.get('text')}")
            click.echo(f"    Time    : {r.get('detected_at')}")


# ========== CLI ==========
@click.group()
def cli():
    """DarkRadar CLI - OSINT & Darkweb Search Tool"""
    pass


@cli.command()
@click.option('--mode', type=click.Choice(['internet', 'darkweb']), default='internet',
              help='Pilih mode pencarian (internet/darkweb)')
@click.option('--keywords', required=True, help='Kata kunci pencarian (comma-separated)')
@click.option('--output', default='search_results.json', help='File output hasil pencarian')
@click.pass_context
def search(ctx, mode, keywords, output):
    all_keywords = [k.strip() for k in keywords.split(',') if k.strip()]
    results = []

    if mode == 'internet':
        click.echo(f"[INFO] Mencari di internet untuk: {all_keywords}")
        results = DataSources.fetch_github_search(all_keywords)

    elif mode == 'darkweb':
        click.echo("[INFO] Mengecek koneksi ke Tor...")
        if not TorUtils.is_tor_running():
            click.echo("[ERROR] Tor tidak aktif atau proxy belum tersedia di 127.0.0.1:9050")
            sys.exit(1)
        click.echo(f"[INFO] Tor aktif ✅. Mencari di darkweb untuk: {all_keywords}")
        results = DarkwebSources.search_darkweb(all_keywords)

    with open(output, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    click.echo(f"\n[OK] {len(results)} hasil ditemukan. Disimpan di {output}")
    print_results(results)


@cli.command()
def check_tor():
    click.echo("[INFO] Mengecek koneksi ke Tor...")
    if TorUtils.is_tor_running():
        click.echo("✅ Tor aktif dan siap dipakai!")
    else:
        click.echo("❌ Tor tidak aktif! Jalankan service Tor dulu.")


# ========== AUTO MODE ==========
if __name__ == "__main__":
    click.echo(BANNER)
    if len(sys.argv) == 1:
        click.echo("Pilih mode scanning:\n")
        click.echo(" [1] Scanning langsung (default keywords)")
        click.echo(" [2] Scanning dari file data.txt\n")
        try:
            pilihan = input("Masukkan pilihan [1/2] : ").strip()
        except KeyboardInterrupt:
            sys.exit("\n[EXIT] Dibatalkan oleh user.")

        # Default keywords (mode 1)
        default_keywords = ["tni", "polri", "indonesia", "leak", "database"]

        # NEW FEATURE : load keywords dari file data.txt
        if pilihan == "2":
            try:
                with open("data.txt", "r", encoding="utf-8") as f:
                    file_keywords = [line.strip() for line in f if line.strip()]
                if not file_keywords:
                    click.echo("[ERROR] data.txt kosong! Menggunakan default keywords.")
                    all_keywords = default_keywords
                else:
                    all_keywords = file_keywords
                    click.echo(f"[INFO] {len(all_keywords)} keyword dimuat dari data.txt ✅")
            except FileNotFoundError:
                click.echo("[ERROR] File data.txt tidak ditemukan! Menggunakan default keywords.")
                all_keywords = default_keywords
        else:
            all_keywords = default_keywords

        click.echo(f"[AUTO] Menjalankan pencarian otomatis untuk: {all_keywords}\n")

        tor_ok = TorUtils.is_tor_running()
        results = []

        click.echo("🌐 Pencarian Internet...")
        internet_results = DataSources.fetch_github_search(all_keywords)
        print_results(internet_results)
        results.extend(internet_results)

        if tor_ok:
            click.echo("\n🕵️‍♂️ Pencarian Darkweb...")
            dark_results = DarkwebSources.search_darkweb(all_keywords)
            print_results(dark_results)
            results.extend(dark_results)
        else:
            click.echo("\n[WARN] Tor tidak aktif, darkweb search dilewati.")

        filename = f"auto_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        click.echo(f"\n[OK] Auto search selesai. Hasil disimpan di {filename}\n")
    else:
        cli()
