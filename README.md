# Shodan_advanced_auditor
Proyek Shodan Advanced Auditor adalah sebuah alat CLI Python untuk melakukan passive security audit multi-target menggunakan Shodan API.
Alat ini menerima satu atau banyak target (IP/domain), mengambil data publik dari Shodan, melakukan analisis sederhana terhadap layanan yang terdeteksi, lalu menghasilkan ringkasan dan laporan terstruktur.

Hasil file : shodan_audit.json

FITUR :

1. Input fleksibel: -t <target> (berulang) atau -f <file> (daftar target, satu per baris).

2. Integrasi Shodan: ambil service banners, daftar port terbuka, OS (jika tersedia), dan lokasi server (negara/kota/koordinat).

3. Analisis keamanan: hitung jumlah port terbuka, tandai port berisiko umum (mis. 21, 22, 23, 445, 3389), dan label layanan berdasarkan kata kunci di banner (mis. ssh, ftp, rdp).

4. Output ganda: ringkasan tabel di terminal dan file JSON terstruktur (shodan_audit.json) berisi detail tiap target (os, lokasi, open_ports, risky_ports, banners, notes).

PENGGUNAAN : 

1. python auditor.py -t example.com

2. python auditor.py -f target.txt.txt

Screenshot powershell :

<img width="1718" height="707" alt="Image" src="https://github.com/user-attachments/assets/4b24d93f-30b0-4c7c-abac-bff6e90688cd" />

Screenshot code json :

<img width="1814" height="958" alt="Image" src="https://github.com/user-attachments/assets/2b62d550-0d2b-4c70-8d5c-202fb84b4064" />
