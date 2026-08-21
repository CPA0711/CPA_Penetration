```
 ⚡ CPA – Powered Penetration Testing Framework
CPA_Penetration adalah framework penetration testing modular dan otomatis yang menggabungkan **reconnaissance, vulnerability scanning, exploitation, dan reporting** dalam satu alat yang powerful.



 🚀 Fitur Utama

| Modul | Deskripsi |
|-------|-----------|
| **🔍 DNS Enumeration** | Subdomain discovery, A/MX/NS/TXT records lookup |
| **📡 Port Scanning** | Fast TCP port scanner (24+ default ports) |
| **🖥️ Technology Fingerprinting** | Deteksi server, framework, CMS, JS libraries |
| **🔓 Vulnerability Scanner** | SQLi, XSS, LFI, RCE, security headers, default credentials |
| **📊 Automated Reporting** | HTML, JSON, Markdown formats |
| **📦 Payload Library** | Built-in payloads for SQLi, XSS, LFI, RCE |
| **⚡ Multi-threading** | Fast scanning with configurable threads |
| **🔄 Async Support** | Non-blocking I/O for faster scanning |



 📦 Prasyarat

- **Python 3.8+**
- **Koneksi internet** (untuk install dependencies & DNS lookup)
- **Sistem yang diuji** harus dimiliki atau memiliki izin tertulis



 ⚙️ Instalasi

1. Clone atau Buat File

```bash
# Buat file cpa.py
nano cpa.py
# Paste seluruh kode script ke dalam file
# Ctrl+X, Y, Enter
```

2. Install Dependencies

```bash
pip install aiohttp colorama dnspython

Atau jika menggunakan pip3
pip3 install aiohttp colorama dnspython
```

3. Verifikasi Instalasi

```bash
python cpa.py --list-payloads
# Harus menampilkan daftar payload yang tersedia
```

---

🎯 Cara Penggunaan

Perintah Dasar

```bash
# Full scan (reconnaissance + vulnerability)
python cpa.py --target example.com --full

# Reconnaissance only (DNS, port, fingerprint)
python cpa.py --target example.com --recon

# Vulnerability scan only
python cpa.py --target example.com --scan

# Dengan report HTML
python cpa.py --target example.com --full --report html -o report.html

# Dengan report JSON
python cpa.py --target example.com --full --report json -o report.json

# Dengan report Markdown
python cpa.py --target example.com --full --report markdown -o report.md

# Debug mode
python cpa.py --target example.com --full --debug

# Lihat payload library
python cpa.py --list-payloads
```

---

⚙️ Parameter Lengkap

Parameter /Deskripsi/ Default/ Contoh

-t, --target Target domain/IP (wajib) – -t example.com

--threads Jumlah  50 --threads 100

--timeout Timeout per request (detik) 10 --timeout 15

--full Jalankan full scan (recon + vuln) – --full

--recon Hanya reconnaissance – --recon

--scan Hanya vulnerability scan – --scan

--report Format laporan: html, json, markdown html --report json

-o, --output Nama file laporan report_{timestamp} -o hasil.json

--debug Tampilkan log detail false --debug

--list-payloads Tampilkan daftar payload – --list-payloads



🔥 Contoh Penggunaan

1. Full Scan dengan Report HTML

```bash
python cpa.py --target example.com --full --report html -o scan_result.html
```

Output:

```
[INFO] Target: example.com
[INFO] Starting reconnaissance phase
[INFO] Enumerating subdomains for example.com
[SUCCESS] Found 12 subdomains
[INFO] Scanning ports on 93.184.216.34 (24 ports)
[SUCCESS] Found 4 open ports
[INFO] Fingerprinting technology stack
[INFO] Starting vulnerability scan
[SUCCESS] Found 3 vulnerabilities
[SUCCESS] Report generated: scan_result.html
```

2. Reconnaissance Only

```bash
python cpa.py --target example.com --recon --threads 100
```

3. Vulnerability Scan with JSON Report

```bash
python cpa.py --target example.com --scan --report json -o vuln.json
```

4. Scan dengan Custom Timeout

```bash
python cpa.py --target example.com --full --timeout 20
```

5. Debug Mode

```bash
python cpa.py --target example.com --full --debug
```

6. Lihat Payload Library

```bash
python cpa.py --list-payloads
```

Output:

```
Available Payloads:

SQL
  ' OR '1'='1
  ' OR 1=1--
  ' UNION SELECT NULL--
  '; DROP TABLE users--
  1' AND SLEEP(5)--
  ... and 0 more

XSS
  <script>alert('XSS')</script>
  <img src=x onerror=alert(1)>
  <svg/onload=alert('XSS')>
  javascript:alert('XSS')
  ... and 0 more
```

---

📊 Format Laporan

HTML Report

Laporan HTML interaktif dengan:

· Executive Summary – ringkasan temuan
· Vulnerabilities by Severity – Critical, High, Medium, Low, Info
· Open Ports – daftar port terbuka
· Subdomains – subdomain yang ditemukan
· Technology Stack – teknologi yang terdeteksi
· DNS Records – A, MX, NS records

JSON Report

```json
{
  "target": "example.com",
  "timestamp": "2025-01-01T12:00:00",
  "open_ports": [
    {"port": 80, "service": "http"},
    {"port": 443, "service": "https"}
  ],
  "subdomains": ["www.example.com", "mail.example.com"],
  "vulnerabilities": [
    {
      "type": "SQL Injection",
      "severity": "High",
      "url": "https://example.com?id=1'",
      "payload": "' OR '1'='1",
      "evidence": "SQL error detected"
    }
  ],
  "tech_stack": {
    "server": "nginx/1.18.0",
    "php": true,
    "wordpress": true
  }
}
```

Markdown Report

File .md yang bisa dibuka di editor teks atau GitHub, dengan struktur:

· Executive Summary
· Vulnerabilities by Severity
· Open Ports
· Subdomains
· DNS Records
· Technology Stack

---

🛠️ Troubleshooting

Masalah Solusi
ModuleNotFoundError Install dependencies: pip install aiohttp colorama dnspython
Target tidak bisa di-resolve Periksa koneksi internet dan DNS, atau gunakan IP langsung
Timeout Tambahkan --timeout 20 atau lebih besar
Port scanning lambat Kurangi --threads atau perbanyak --timeout
SSL Error Script sudah pakai ssl=False, tapi pastikan target bisa diakses
Report tidak terbentuk Cek permission folder, jalankan dengan sudo jika perlu
dnspython error Install dengan pip install dnspython
asyncio error Pastikan Python 3.8+

---

⚠️ Disclaimer

Aspek Keterangan
Legalitas Hanya untuk testing di sistem sendiri atau dengan izin tertulis
Etika Jangan gunakan untuk merusak, mencuri data, atau aktivitas ilegal
Tanggung Jawab Pengguna bertanggung jawab penuh atas penggunaan
Sanksi Penggunaan tanpa izin adalah ILEGAL dan dapat dikenai sanksi pidana

---

📄 Lisensi

MIT License – Gunakan dengan bijak dan bertanggung jawab.

---

🙋 Kontribusi

Pull request dan saran fitur baru selalu diterima. Buat issue untuk diskusi lebih lanjut.

---

🔗 Tautan Berguna

· AIOHTTP Documentation
· Colorama Documentation
· DNSPython Documentation

---

🔥 CPA – Powered Penetration Testing Framework siap digunakan! 🚀

---

📌 Ringkasan Perintah Cepat

```bash
# Full scan + HTML report
python cpa.py -t example.com --full

# Full scan + JSON report
python cpa.py -t example.com --full --report json -o hasil.json

# Recon only
python cpa.py -t example.com --recon

# Scan only
python cpa.py -t example.com --scan

# Dengan custom thread & timeout
python cpa.py -t example.com --full --threads 100 --timeout 15

# Debug mode
python cpa.py -t example.com --full --debug

# List payloads
python cpa.py --list-payloads
```

---

“Reveal the unseen.” 🔍

```
