# 🛰️ NetScout — Network Analysis Tool

Tool analisis jaringan berbasis Streamlit dengan 5 modul utama untuk keperluan network diagnostics dan security auditing.

## ✨ Fitur

| Modul | Fungsi |
|-------|--------|
| 🔍 Port Scanner | Multi-threaded TCP port scan dengan deteksi service |
| 🌐 DNS & WHOIS | Query semua tipe DNS record + WHOIS domain info |
| 🔒 SSL Certificate | Cek validitas, issuer, cipher suite, dan SAN |
| 📋 HTTP Headers | Analisis security headers (HSTS, CSP, X-Frame-Options, dll) |
| 📡 Ping & Traceroute | ICMP reachability + network path tracing |

## 🚀 Deploy ke Streamlit Community Cloud

### 1. Push ke GitHub

```bash
# Buat repo baru di GitHub, lalu:
git init
git add .
git commit -m "Initial commit: NetScout"
git remote add origin https://github.com/USERNAME/netscout.git
git push -u origin main
```

### 2. Deploy di Streamlit Cloud

1. Buka [share.streamlit.io](https://share.streamlit.io)
2. Klik **"New app"**
3. Pilih repo GitHub Anda
4. Set **Main file path** → `app.py`
5. Klik **"Deploy!"**

### 3. Struktur File

```
netscout/
├── app.py              ← Main application
├── requirements.txt    ← Python dependencies
├── packages.txt        ← System packages (ping, traceroute)
├── README.md
└── .streamlit/
    └── config.toml     ← Theme configuration
```

## ⚠️ Legal Disclaimer

Tool ini **hanya boleh digunakan** pada sistem atau jaringan yang:
- Anda miliki sendiri, atau
- Anda memiliki **izin tertulis** dari pemiliknya untuk melakukan pengujian

Penggunaan tanpa izin terhadap sistem orang lain adalah **tindakan ilegal** dan dapat dikenakan sanksi hukum.

## 🛠️ Run Locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

## 📦 Dependencies

- `streamlit` — UI framework
- `dnspython` — DNS queries
- `python-whois` — WHOIS lookups
- `requests` — HTTP analysis
- `iputils-ping` + `traceroute` — System tools (via packages.txt)
