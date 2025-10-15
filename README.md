<img width="874" height="184" alt="ascii-art-text" src="https://github.com/user-attachments/assets/4433b520-a904-4fa4-bc0d-96cbb66c791b" />




DarkRadar adalah **OSINT & Darkweb Search Tool** untuk mengumpulkan informasi dari internet dan darkweb (via Tor).  
Tools ini membantu melakukan **deteksi dini potensi kebocoran data** — termasuk kemungkinan **kebocoran data pemerintah, militer, atau infrastruktur kritis** yang sering diperjualbelikan di forum gelap.  

---

## ✨ Fitur
- Scanning otomatis dengan **default keywords** atau **custom keywords dari file txt**.
- Internet search untuk mencari potensi kebocoran kode/data publik.
- Darkweb search (Ahmia) untuk menelusuri forum gelap (hanya jika Tor aktif).
- Menampilkan hasil realtime.
- Menyimpan hasil ke file JSON dengan nama unik (`auto_results_YYYYMMDD_HHMMSS.json`).
- Mode manual via perintah CLI (internet / darkweb).
- Osint Sosial Media

---

## 📦 Instalasi
1. Clone repo ini
  
   git clone https://github.com/username/darkradar.git
   cd darkradar

2. Install dependency

   pip install -r requirements.txt
   Atau manual:
   pip install requests click

3. Pastikan Tor service berjalan di 127.0.0.1:9050

   sudo service tor start


🚀 Cara Penggunaan

1. Mode Otomatis

   python3 darkradar.py

2. Mode Manual CLI

   🔍 Internet Search
   python3 darkradar.py search --mode internet --keywords "indonesia,leak,password"

   🕵️ Darkweb Search
   python3 darkradar.py search --mode darkweb --keywords "indonesia,leak"

   ✅ Check Tor
   python3 darkradar.py check-tor

⚠️ Disclaimer

Tool ini dibuat untuk tujuan pembelajaran, riset keamanan, dan deteksi dini ancaman.
Segala penyalahgunaan (termasuk eksploitasi kebocoran data) menjadi tanggung jawab pengguna.

👨‍💻 Author: @YogaGymn @Bear Cyber Hunt




 
