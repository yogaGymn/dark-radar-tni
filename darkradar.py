#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import requests
import click
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

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

        def worker(keyword):
            url = f"https://api.github.com/search/code?q={keyword}"
            try:
                resp = requests.get(url, timeout=20)
                if resp.status_code == 200:
                    res = {
                        "source": "internet/github",
                        "url": url,
                        "text": f"Hasil pencarian GitHub untuk: {keyword}",
                        "detected_at": datetime.utcnow().isoformat()
                    }
                    print_results([res])  # realtime
                    return res
                else:
                    res = {
                        "source": "internet/github",
                        "error": f"HTTP {resp.status_code}",
                        "keyword": keyword
                    }
                    print_results([res])  # realtime
                    return res
            except Exception as e:
                res = {
                    "source": "internet/github",
                    "error": str(e),
                    "keyword": keyword
                }
                print_results([res])  # realtime
                return res

        if not keywords:
            return results

        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = [ex.submit(worker, k) for k in keywords]
            for f in as_completed(futures):
                try:
                    results.append(f.result())
                except Exception as e:
                    results.append({"source": "internet/github", "error": str(e)})
        return results

    @staticmethod
    def fetch_multi_search(keywords, include_social=True):
        """
        include_social=False -> skip facebook, instagram, tiktok
        """
        results = []
        targets = [
            "https://www.google.com/search?q=",
            "https://tni.mil.id/search?q=",
            "https://webmail.tni.mil.id/search?q=",
            "https://webdisk.tni.mil.id/search?q=",
            "https://puspen.tni.mil.id/search?q=",
            "https://nms.tni.mil.id/search?q=",
            "https://mx2.tni.mil.id/search?q=",
            "https://mediaanalis.tni.mil.id/search?q=",
            "https://main-mx.tni.mil.id/search?q=",
            "https://jdih.tni.mil.id/search?q=",
        ]

        if include_social:
            targets.extend([
                "https://facebook.com/search?q=",
                "https://instagram.com/explore/tags/",
                "https://www.tiktok.com/tag/"
            ])

        if not keywords:
            return results

        def worker(base, keyword):
            url = f"{base}{keyword}"
            host = base.split("//")[1].split("/")[0]
            src = f"internet/{host}"
            try:
                resp = requests.get(url, timeout=20)
                if resp.status_code == 200:
                    res = {
                        "source": src,
                        "url": url,
                        "text": f"Hasil pencarian di {host} untuk: {keyword}",
                        "detected_at": datetime.utcnow().isoformat()
                    }
                    print_results([res])  # realtime
                    return res
                else:
                    res = {
                        "source": src,
                        "error": f"HTTP {resp.status_code}",
                        "keyword": keyword
                    }
                    print_results([res])  # realtime
                    return res
            except Exception as e:
                res = {
                    "source": src,
                    "error": str(e),
                    "keyword": keyword
                }
                print_results([res])  # realtime
                return res

        tasks = []
        with ThreadPoolExecutor(max_workers=30) as ex:
            for keyword in keywords:
                for base in targets:
                    tasks.append(ex.submit(worker, base, keyword))

            for f in as_completed(tasks):
                try:
                    results.append(f.result())
                except Exception as e:
                    results.append({"source": "internet/multi", "error": str(e)})

        return results


# ========== DARKWEB SOURCES ==========
class DarkwebSources:
    TOR_PROXY = TorUtils.TOR_PROXY

    @staticmethod
    def search_darkweb(keywords):
        results = []
        if not keywords:
            return results

        def worker(keyword):
            url = f"https://ahmia.fi/search/?q={keyword}"
            try:
                resp = requests.get(url, proxies=DarkwebSources.TOR_PROXY, timeout=30)
                if resp.status_code == 200:
                    res = {
                        "source": "darkweb/ahmia",
                        "url": url,
                        "text": f"Hasil pencarian di Ahmia untuk: {keyword}",
                        "detected_at": datetime.utcnow().isoformat()
                    }
                    print_results([res])  # realtime
                    return res
                else:
                    res = {
                        "source": "darkweb/ahmia",
                        "error": f"HTTP {resp.status_code}",
                        "keyword": keyword
                    }
                    print_results([res])  # realtime
                    return res
            except Exception as e:
                res = {
                    "source": "darkweb/ahmia",
                    "error": str(e),
                    "keyword": keyword
                }
                print_results([res])  # realtime
                return res

        with ThreadPoolExecutor(max_workers=10) as ex:
            futures = [ex.submit(worker, k) for k in keywords]
            for f in as_completed(futures):
                try:
                    results.append(f.result())
                except Exception as e:
                    results.append({"source": "darkweb/ahmia", "error": str(e)})

        return results


# ========== HELPER OUTPUT ==========
def print_results(results):
    if not results:
        click.secho("   [!] Tidak ada hasil.", fg="yellow")
        return

    for i, r in enumerate(results, 1):
        click.secho(f"\n[{i}] Source : {r.get('source')}", fg="magenta")
        if "error" in r:
            click.secho(f"    ❌ Error : {r['error']}", fg="red")
            if "keyword" in r:
                click.secho(f"    🔎 Keyword : {r['keyword']}", fg="yellow")
        else:
            click.secho(f"    ✅ URL   : {r.get('url')}", fg="cyan")
            click.secho(f"    Info    : {r.get('text')}", fg="green")
            click.secho(f"    Time    : {r.get('detected_at')}", fg="yellow")


# ========== CLI ==========
@click.group()
def cli():
    pass


@cli.command()
@click.option('--mode', type=click.Choice(['internet', 'darkweb']), default='internet')
@click.option('--keywords', required=True, help='Kata kunci pencarian (comma-separated)')
@click.option('--output', default='search_results.json')
@click.pass_context
def search(ctx, mode, keywords, output):
    all_keywords = [k.strip() for k in keywords.split(',') if k.strip()]
    results = []

    if mode == 'internet':
        click.echo(f"[INFO] Mencari di internet untuk: {all_keywords}")
        github_results = DataSources.fetch_github_search(all_keywords)
        multi_results = DataSources.fetch_multi_search(all_keywords, include_social=True)
        results = github_results + multi_results

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


@cli.command()
def check_tor():
    click.echo("[INFO] Mengecek koneksi ke Tor...")
    if TorUtils.is_tor_running():
        click.echo("✅ Tor aktif dan siap dipakai!")
    else:
        click.echo("❌ Tor tidak aktif! Jalankan service Tor dulu.")


# ========== AUTO MODE ==========
if __name__ == "__main__":
    banner_lines = BANNER.splitlines()
    split_index = max(0, len(banner_lines) - 3)
    for idx, line in enumerate(banner_lines):
        if idx < split_index:
            click.secho(line, fg="red")
        else:
            click.secho(line, fg="white")

    if len(sys.argv) == 1:
        click.echo("Pilih mode scanning:\n")
        click.echo(" [1] Scanning langsung (default keywords)")
        click.echo(" [2] Scanning dari file data.txt")
        click.echo(" [3] Scanning dari file sensitive data.txt")
        click.echo(" [4] OSINT Sosial Media (osint.txt)\n")
        try:
            pilihan = input("Masukkan pilihan [1/2/3/4] : ").strip()
        except KeyboardInterrupt:
            sys.exit("\n[EXIT] Dibatalkan oleh user.")

        default_keywords = [
            "NIK",
            "No. KTP",
            "tanggal lahir",
            "tempat lahir",
            "nama ibu kandung",
            "alamat",
            "NPWP",
            "SIM",
            "Paspor",
            "kartu keluarga",
            "biodata",
            "rekam_medis",
            "data biometrik",
            "sidik jari",
            "retina scan",
            "DNA",
            "Face ID",
            "Voice recognition",
            "Kartu Kredit",
            "Nomor Rekening Bank",
            "Nomor kartu debit",
            "CVV",
            "CVC",
            "Saldo e-wallet",
            "Virtual account",
            "Swift code",
            "IBAN",
            "Nomor polis",
            "Nomor asuransi",
            "password",
            "username",
            "credential",
            "API Key",
            "Token",
            "Sertifikat SSL",
            "file .pem",
            "SSH key",
            "Token otentikasi",
            "Root password",
            "Admin password",
            "Cloud key",
            "OAuth token",
            "JWT",
            "Access token",
            "Database dump",
            ".env file",
            "Private key",
            "Nomor BPJS Kesehatan",
            "Diagnosis medis",
            "Resep obat",
            "Hasil lab"
        ]

        if pilihan == "2":
            try:
                with open("data.txt", "r", encoding="utf-8") as f:
                    file_keywords = [line.strip() for line in f if line.strip()]
                all_keywords = file_keywords if file_keywords else default_keywords
            except FileNotFoundError:
                all_keywords = default_keywords

        elif pilihan == "3":
            try:
                with open("sensitive data.txt", "r", encoding="utf-8") as f:
                    sensitive_keywords = [line.strip() for line in f if line.strip()]
                if not sensitive_keywords:
                    sys.exit(1)
                all_keywords = sensitive_keywords
            except FileNotFoundError:
                sys.exit(1)

        elif pilihan == "4":
            try:
                with open("osint.txt", "r", encoding="utf-8") as f:
                    osint_keywords = [line.strip() for line in f if line.strip()]
                if not osint_keywords:
                    sys.exit(1)
                all_keywords = osint_keywords
                click.secho(f"[INFO] {len(all_keywords)} keyword dimuat dari osint.txt ✅", fg="green")
            except FileNotFoundError:
                sys.exit(1)

        else:
            all_keywords = default_keywords
            click.secho("[AUTO] Menjalankan pencarian otomatis (default keywords)...\n", fg="green")

        tor_ok = TorUtils.is_tor_running()
        results = []

        click.secho("🌐 Pencarian Internet...", fg="cyan")

        if pilihan == "4":
            multi_results = DataSources.fetch_multi_search(all_keywords, include_social=True)
            results.extend(multi_results)
        else:
            github_results = DataSources.fetch_github_search(all_keywords)
            multi_results = DataSources.fetch_multi_search(all_keywords, include_social=False)
            results.extend(github_results + multi_results)

        if tor_ok:
            click.secho("\n🕵️‍♂️ Pencarian Darkweb (Tor aktif)...", fg="cyan")
            dark_results = DarkwebSources.search_darkweb(all_keywords)
            results.extend(dark_results)
        else:
            click.secho("\n[WARN] Tor tidak aktif, darkweb search dilewati.", fg="yellow")

        filename = f"auto_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)

        click.secho(f"\n[OK] Auto search selesai. Hasil disimpan di {filename}\n", fg="green")
    else:
        cli()
