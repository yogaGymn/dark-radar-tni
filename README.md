<img width="874" height="184" alt="ascii-art-text" src="https://github.com/user-attachments/assets/4433b520-a904-4fa4-bc0d-96cbb66c791b" />


# dark-radar-tni
Dark Radar TNI adalah sebuah tool untuk memproses dan menampilkan data radar dari berbagai sumber feed yang mengalami kebocoran.
Project ini dibuat menggunakan Python dan dapat dijalankan baik di Windows maupun Linux.

✨ Fitur

🚀 Mendukung konfigurasi melalui file YAML

📡 Membaca data dari feed.json

⚙️ Dapat dijalankan via script Python atau batch file

💻 Cross-platform (Windows & Linux)

⌚ Realtime crawler untuk domain/subdomain TNI.

🔎 Deteksi data sensitif (NIK, email, IP, credit card, password/token, telepon, NRP, koordinat).

💯 Skor risiko gabungan (keyword rules + sensitive patterns).

📜 Output rapi, bertingkat, mudah dianalisis.

🛠️ Perbaikan bug response yang tidak didefinisikan.

🎆 Penanganan error & timeout yang aman.

🕹️ Opsi interval realtime via --interval.


📦 Persyaratan

Python 3.8 atau lebih baru

Git (opsional, untuk clone repo)

Virtual environment (disarankan)

⚙️ Instalasi
1. Clone Repository
git clone https://github.com/yogaGymn/dark-radar-tni.git
cd dark-radar-tni

3. Buat Virtual Environment
Linux / MacOS :
python3 -m venv .venv
source .venv/bin/activate

Windows (PowerShell)
python -m venv .venv
.venv\Scripts\Activate

3. Install Dependencies
pip install -r requirements.txt

🚀 Cara Menjalankan

Linux / MacOS :
python3 darkradar.py

Windows (CMD / PowerShell) :
python darkradar.py
Atau dengan file batch:
darkradar_run.bat

🚀 Cara Menjalankan Otomatis semua
python darkradar.py realtime --interval 120 

 
