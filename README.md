
---

```markdown
# 🔥 Auto Nmap Scanner

Script Python sederhana untuk menjalankan **Nmap** secara otomatis dengan berbagai pilihan scan.  
Dilengkapi banner ASCII keren + opsi simpan hasil ke file (txt/xml/gnmap) + ekstraksi port terbuka ke CSV.  

---

## 👁️ Banner
```

```

---

## 🚀 Fitur
- Pilihan scan lengkap (Ping, SYN, TCP, UDP, Aggressive, Script scan, dll).
- Mode **Basic Scan** (otomatis pilih -sT atau -sS sesuai root).
- Output ke **TXT**, **XML**, dan **GNMAP**.
- Ekstraksi port terbuka langsung ke **CSV**.
- Banner ASCII **Devil Eye + DELFI BOYZ**.

---

## 📦 Instalasi
Pastikan sudah menginstal Python dan Nmap:

```bash
sudo apt update
sudo apt install nmap python3 -y
````

Clone repo (atau simpan script):

```bash
git clone https://github.com/username/auto-nmap.git
cd auto-nmap
```

---

## ⚡ Cara Menjalankan

```bash
python3 auto_nmap.py
```

Pilih jenis scan di menu:

* **1** → Ping scan
* **2** → TCP Connect scan
* **3** → SYN Stealth scan
* **4** → UDP scan
* **5** → Aggressive scan
* **6** → Fast scan
* **7** → Full TCP scan
* **8** → Custom port
* **9** → Script scan
* **10 / b** → Basic scan

---

## 📂 Output

* `scan_result.txt` → hasil normal
* `scan_result.xml` → hasil XML
* `scan_result.gnmap` → hasil GNMAP
* `scan_result.csv` → port terbuka (IP, Port, Protocol, Service)

---

## ⚠️ Disclaimer

Script ini hanya untuk **pembelajaran & testing sistem milik sendiri**.
Penulis tidak bertanggung jawab atas penyalahgunaan.

---

👤 Dibuat oleh **Delfi Boyz**

```
