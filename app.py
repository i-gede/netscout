import streamlit as st
import socket
import ssl
import subprocess
import dns.resolver
import dns.rdatatype
import whois
import requests
import concurrent.futures
import time
import json
from datetime import datetime
import ipaddress

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="NetScout – Network Analysis Tool",
    page_icon="🛰️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

html, body, [class*="css"] {
    font-family: 'IBM Plex Sans', sans-serif;
}

/* Dark terminal theme */
.stApp {
    background-color: #0d1117;
    color: #c9d1d9;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background-color: #161b22;
    border-right: 1px solid #21262d;
}

[data-testid="stSidebar"] .stRadio label {
    color: #8b949e !important;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.82rem;
}

/* Headers */
h1 { 
    font-family: 'IBM Plex Mono', monospace !important;
    color: #58a6ff !important;
    letter-spacing: -0.5px;
    font-size: 1.6rem !important;
}
h2, h3 { 
    font-family: 'IBM Plex Mono', monospace !important;
    color: #79c0ff !important;
    font-size: 1.1rem !important;
}

/* Cards */
.result-card {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 1.2rem 1.4rem;
    margin-bottom: 0.8rem;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.83rem;
}

.result-card.success { border-left: 3px solid #3fb950; }
.result-card.danger  { border-left: 3px solid #f85149; }
.result-card.warning { border-left: 3px solid #d29922; }
.result-card.info    { border-left: 3px solid #58a6ff; }

.badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 20px;
    font-size: 0.72rem;
    font-family: 'IBM Plex Mono', monospace;
    font-weight: 600;
    margin-left: 6px;
}
.badge-open    { background: #1a3a1a; color: #3fb950; border: 1px solid #238636; }
.badge-closed  { background: #3a1a1a; color: #f85149; border: 1px solid #6e2c2c; }
.badge-filtered{ background: #3a2a1a; color: #d29922; border: 1px solid #6e5228; }

.mono { font-family: 'IBM Plex Mono', monospace; font-size: 0.82rem; color: #8b949e; }
.val  { color: #79c0ff; font-weight: 500; }
.ok   { color: #3fb950; }
.err  { color: #f85149; }
.warn { color: #d29922; }

.section-label {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.68rem;
    text-transform: uppercase;
    letter-spacing: 2px;
    color: #30363d;
    border-bottom: 1px solid #21262d;
    padding-bottom: 6px;
    margin-bottom: 12px;
}

/* Inputs */
.stTextInput input, .stNumberInput input {
    background: #161b22 !important;
    border: 1px solid #30363d !important;
    color: #c9d1d9 !important;
    font-family: 'IBM Plex Mono', monospace !important;
    border-radius: 4px !important;
}

/* Buttons */
.stButton > button {
    background: #21262d !important;
    color: #58a6ff !important;
    border: 1px solid #30363d !important;
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 0.82rem !important;
    border-radius: 4px !important;
    transition: all 0.15s;
}
.stButton > button:hover {
    background: #30363d !important;
    border-color: #58a6ff !important;
}

/* Expander */
.streamlit-expanderHeader {
    font-family: 'IBM Plex Mono', monospace !important;
    background: #161b22 !important;
    border: 1px solid #21262d !important;
    color: #8b949e !important;
    font-size: 0.82rem !important;
}

/* Table */
.stDataFrame { font-family: 'IBM Plex Mono', monospace; font-size: 0.78rem; }

/* Disclaimer banner */
.disclaimer {
    background: #1c1a00;
    border: 1px solid #9e6a03;
    border-radius: 6px;
    padding: 0.8rem 1.2rem;
    font-size: 0.78rem;
    color: #e3b341;
    font-family: 'IBM Plex Mono', monospace;
    margin-bottom: 1.2rem;
}

/* Progress */
.stProgress > div > div { background: #1f6feb !important; }

/* Metric */
[data-testid="stMetric"] {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 0.8rem 1rem;
}
[data-testid="stMetricLabel"] { color: #8b949e !important; font-family: 'IBM Plex Mono', monospace !important; font-size: 0.72rem !important; }
[data-testid="stMetricValue"] { color: #58a6ff !important; font-family: 'IBM Plex Mono', monospace !important; }
</style>
""", unsafe_allow_html=True)

# ── Helpers ───────────────────────────────────────────────────────────────────

def resolve_host(host: str) -> str | None:
    """Resolve hostname to IP."""
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def is_valid_target(target: str) -> bool:
    """Basic validation – no private ranges enforcement (user responsibility)."""
    return bool(target.strip())

def scan_port(host: str, port: int, timeout: float = 1.0) -> tuple[int, str]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
    status = "open" if result == 0 else "closed"
    return port, status

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 587: "SMTP-TLS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "Jupyter", 9200: "Elasticsearch", 27017: "MongoDB",
}

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛰️ NetScout")
    st.markdown('<p class="mono">Network Analysis Tool v1.0</p>', unsafe_allow_html=True)
    st.markdown("---")

    tool = st.radio(
        "SELECT MODULE",
        options=[
            "🔍  Port Scanner",
            "🌐  DNS & WHOIS",
            "🔒  SSL Certificate",
            "📋  HTTP Headers",
            "📡  Ping & Traceroute",
        ],
        label_visibility="visible",
    )

    st.markdown("---")
    st.markdown("""
    <div style="font-family:'IBM Plex Mono',monospace;font-size:0.7rem;color:#30363d;line-height:1.8">
    ⚠ Untuk penggunaan pada<br>
    sistem yang Anda miliki<br>
    atau memiliki izin resmi.<br><br>
    Unauthorized scanning<br>
    adalah tindakan ilegal.
    </div>
    """, unsafe_allow_html=True)

# ── Disclaimer ────────────────────────────────────────────────────────────────
st.markdown("""
<div class="disclaimer">
⚠️  <strong>DISCLAIMER</strong> — Tool ini hanya boleh digunakan pada sistem/jaringan yang Anda miliki atau memiliki izin tertulis untuk melakukan pengujian.
Penggunaan tanpa izin terhadap sistem orang lain adalah <strong>tindakan ilegal</strong> dan melanggar hukum yang berlaku.
</div>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# MODULE 1 – PORT SCANNER
# ══════════════════════════════════════════════════════════════════════════════
if "Port Scanner" in tool:
    st.markdown("# Port Scanner")
    st.markdown('<p class="mono">Scan open TCP ports on a target host</p>', unsafe_allow_html=True)

    col1, col2 = st.columns([3, 1])
    with col1:
        target = st.text_input("Target (IP or hostname)", placeholder="e.g. 192.168.1.1 or example.com")
    with col2:
        scan_mode = st.selectbox("Mode", ["Common Ports", "Custom Range"])

    if scan_mode == "Custom Range":
        c1, c2 = st.columns(2)
        with c1:
            port_start = st.number_input("Start Port", min_value=1, max_value=65534, value=1)
        with c2:
            port_end = st.number_input("End Port", min_value=2, max_value=65535, value=1024)
        ports_to_scan = list(range(int(port_start), int(port_end) + 1))
    else:
        ports_to_scan = list(COMMON_PORTS.keys())

    col_btn, col_threads = st.columns([2, 1])
    with col_btn:
        run_scan = st.button("▶  Run Port Scan", use_container_width=True)
    with col_threads:
        threads = st.number_input("Threads", min_value=10, max_value=200, value=50, step=10)

    if run_scan:
        if not target:
            st.error("Masukkan target terlebih dahulu.")
        else:
            ip = resolve_host(target)
            if not ip:
                st.error(f"Tidak dapat me-resolve host: `{target}`")
            else:
                st.markdown(f'<p class="mono">Resolved <span class="val">{target}</span> → <span class="val">{ip}</span></p>', unsafe_allow_html=True)

                progress = st.progress(0, text="Scanning…")
                results = []
                total = len(ports_to_scan)

                with concurrent.futures.ThreadPoolExecutor(max_workers=int(threads)) as executor:
                    futures = {executor.submit(scan_port, ip, p): p for p in ports_to_scan}
                    done = 0
                    for future in concurrent.futures.as_completed(futures):
                        port, status = future.result()
                        results.append((port, status))
                        done += 1
                        progress.progress(done / total, text=f"Scanned {done}/{total} ports…")

                progress.empty()
                results.sort(key=lambda x: x[0])
                open_ports = [(p, s) for p, s in results if s == "open"]

                # Summary metrics
                m1, m2, m3 = st.columns(3)
                m1.metric("Total Scanned", total)
                m2.metric("Open Ports", len(open_ports))
                m3.metric("Closed/Filtered", total - len(open_ports))

                st.markdown("---")

                if open_ports:
                    st.markdown("### Open Ports")
                    for port, status in open_ports:
                        service = COMMON_PORTS.get(port, "unknown")
                        st.markdown(f"""
                        <div class="result-card success">
                            <span class="val">{port}</span>/tcp
                            <span class="badge badge-open">OPEN</span>
                            <span class="mono" style="margin-left:12px">service: <span class="val">{service}</span></span>
                        </div>
                        """, unsafe_allow_html=True)
                else:
                    st.markdown('<div class="result-card warning">Tidak ada port terbuka yang ditemukan pada range yang di-scan.</div>', unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2 – DNS & WHOIS
# ══════════════════════════════════════════════════════════════════════════════
elif "DNS" in tool:
    st.markdown("# DNS & WHOIS Lookup")
    st.markdown('<p class="mono">Query DNS records and domain registration info</p>', unsafe_allow_html=True)

    target = st.text_input("Domain", placeholder="e.g. google.com")
    col1, col2 = st.columns(2)
    with col1:
        run_dns = st.button("▶  DNS Lookup", use_container_width=True)
    with col2:
        run_whois = st.button("▶  WHOIS Lookup", use_container_width=True)

    if run_dns and target:
        st.markdown("### DNS Records")
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 8

        for rtype in record_types:
            try:
                answers = resolver.resolve(target, rtype)
                records = [str(r) for r in answers]
                color = "info"
                st.markdown(f"""
                <div class="result-card {color}">
                    <span class="section-label">{rtype}</span><br>
                    {'<br>'.join(f'<span class="val">{r}</span>' for r in records)}
                </div>
                """, unsafe_allow_html=True)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except Exception as e:
                pass

        # Reverse DNS
        try:
            ip = socket.gethostbyname(target)
            rev = socket.gethostbyaddr(ip)
            st.markdown(f"""
            <div class="result-card info">
                <span class="section-label">REVERSE DNS</span><br>
                <span class="mono">IP: <span class="val">{ip}</span></span><br>
                <span class="mono">PTR: <span class="val">{rev[0]}</span></span>
            </div>
            """, unsafe_allow_html=True)
        except Exception:
            pass

    if run_whois and target:
        st.markdown("### WHOIS Information")
        try:
            w = whois.whois(target)
            fields = {
                "Registrar": w.registrar,
                "Creation Date": str(w.creation_date),
                "Expiration Date": str(w.expiration_date),
                "Updated Date": str(w.updated_date),
                "Name Servers": w.name_servers,
                "Status": w.status,
                "Emails": w.emails,
                "Country": w.country,
                "Org": w.org,
            }
            rows = ""
            for k, v in fields.items():
                if v:
                    val = ", ".join(v) if isinstance(v, list) else str(v)
                    rows += f'<tr><td class="mono" style="padding:4px 12px 4px 0;color:#8b949e">{k}</td><td class="mono val">{val[:120]}</td></tr>'
            st.markdown(f"""
            <div class="result-card info">
                <span class="section-label">WHOIS DATA – {target}</span>
                <table style="border-collapse:collapse;width:100%">{rows}</table>
            </div>
            """, unsafe_allow_html=True)
        except Exception as e:
            st.markdown(f'<div class="result-card danger">WHOIS lookup gagal: {e}</div>', unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# MODULE 3 – SSL CERTIFICATE
# ══════════════════════════════════════════════════════════════════════════════
elif "SSL" in tool:
    st.markdown("# SSL/TLS Certificate Checker")
    st.markdown('<p class="mono">Inspect TLS certificates and cipher suites</p>', unsafe_allow_html=True)

    col1, col2 = st.columns([3, 1])
    with col1:
        target = st.text_input("Hostname", placeholder="e.g. github.com")
    with col2:
        port = st.number_input("Port", value=443, min_value=1, max_value=65535)

    if st.button("▶  Check Certificate", use_container_width=True):
        if not target:
            st.error("Masukkan hostname.")
        else:
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((target, int(port)), timeout=8) as sock:
                    with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                        cert = ssock.getpeercert()
                        cipher = ssock.cipher()
                        proto = ssock.version()

                # Parse dates
                not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (not_after - datetime.utcnow()).days
                valid_status = "success" if days_left > 30 else ("warning" if days_left > 0 else "danger")

                # Subject & Issuer
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                san_list = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]

                st.markdown(f"""
                <div class="result-card {valid_status}">
                    <span class="section-label">VALIDITY</span>
                    <span class="mono">Not Before: <span class="val">{not_before.strftime('%Y-%m-%d')}</span></span><br>
                    <span class="mono">Not After:  <span class="val">{not_after.strftime('%Y-%m-%d')}</span></span><br>
                    <span class="mono">Days Left:  <span class="{'ok' if days_left>30 else ('warn' if days_left>0 else 'err')}">{days_left} days</span></span>
                </div>
                """, unsafe_allow_html=True)

                st.markdown(f"""
                <div class="result-card info">
                    <span class="section-label">SUBJECT</span>
                    {'<br>'.join(f'<span class="mono">{k}: <span class="val">{v}</span></span>' for k, v in subject.items())}
                </div>
                """, unsafe_allow_html=True)

                st.markdown(f"""
                <div class="result-card info">
                    <span class="section-label">ISSUER</span>
                    {'<br>'.join(f'<span class="mono">{k}: <span class="val">{v}</span></span>' for k, v in issuer.items())}
                </div>
                """, unsafe_allow_html=True)

                st.markdown(f"""
                <div class="result-card info">
                    <span class="section-label">CIPHER &amp; PROTOCOL</span>
                    <span class="mono">Protocol: <span class="val">{proto}</span></span><br>
                    <span class="mono">Cipher:   <span class="val">{cipher[0]}</span></span><br>
                    <span class="mono">Bits:     <span class="val">{cipher[2]}</span></span>
                </div>
                """, unsafe_allow_html=True)

                if san_list:
                    st.markdown(f"""
                    <div class="result-card info">
                        <span class="section-label">SUBJECT ALT NAMES ({len(san_list)})</span>
                        {'<br>'.join(f'<span class="val">• {s}</span>' for s in san_list[:20])}
                        {'<span class="mono">…and more</span>' if len(san_list) > 20 else ''}
                    </div>
                    """, unsafe_allow_html=True)

            except ssl.SSLCertVerificationError as e:
                st.markdown(f'<div class="result-card danger">❌ Certificate verification failed: {e}</div>', unsafe_allow_html=True)
            except Exception as e:
                st.markdown(f'<div class="result-card danger">❌ Error: {e}</div>', unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# MODULE 4 – HTTP HEADERS
# ══════════════════════════════════════════════════════════════════════════════
elif "HTTP" in tool:
    st.markdown("# HTTP Headers Analyzer")
    st.markdown('<p class="mono">Inspect HTTP response headers and security posture</p>', unsafe_allow_html=True)

    col1, col2 = st.columns([3, 1])
    with col1:
        target = st.text_input("URL", placeholder="e.g. https://example.com")
    with col2:
        method = st.selectbox("Method", ["GET", "HEAD"])

    follow_redirects = st.checkbox("Follow redirects", value=True)

    if st.button("▶  Analyze Headers", use_container_width=True):
        if not target:
            st.error("Masukkan URL.")
        else:
            url = target if target.startswith("http") else f"https://{target}"
            try:
                r = requests.request(
                    method, url,
                    allow_redirects=follow_redirects,
                    timeout=10,
                    headers={"User-Agent": "NetScout/1.0 (Security Analysis)"},
                )

                status_color = "success" if r.status_code < 400 else "danger"
                st.markdown(f"""
                <div class="result-card {status_color}">
                    <span class="section-label">RESPONSE</span>
                    <span class="mono">Status: <span class="val">{r.status_code} {r.reason}</span></span><br>
                    <span class="mono">URL:    <span class="val">{r.url}</span></span>
                </div>
                """, unsafe_allow_html=True)

                # Security headers check
                SECURITY_HEADERS = {
                    "Strict-Transport-Security": "HSTS",
                    "Content-Security-Policy": "CSP",
                    "X-Frame-Options": "Clickjacking Protection",
                    "X-Content-Type-Options": "MIME Sniffing Protection",
                    "Referrer-Policy": "Referrer Policy",
                    "Permissions-Policy": "Permissions Policy",
                    "X-XSS-Protection": "XSS Protection",
                }

                st.markdown("### Security Headers")
                for hdr, label in SECURITY_HEADERS.items():
                    val = r.headers.get(hdr)
                    if val:
                        st.markdown(f"""
                        <div class="result-card success">
                            <span class="mono ok">✔ {label}</span>
                            <span class="badge badge-open">PRESENT</span><br>
                            <span class="mono" style="color:#484f58">{hdr}: <span style="color:#8b949e">{val[:100]}</span></span>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.markdown(f"""
                        <div class="result-card danger">
                            <span class="mono err">✖ {label}</span>
                            <span class="badge badge-closed">MISSING</span>
                        </div>
                        """, unsafe_allow_html=True)

                # All headers
                with st.expander("📋  All Response Headers"):
                    rows = ""
                    for k, v in sorted(r.headers.items()):
                        rows += f'<tr><td class="mono" style="padding:3px 14px 3px 0;color:#8b949e;white-space:nowrap">{k}</td><td class="mono val">{v}</td></tr>'
                    st.markdown(f'<table style="border-collapse:collapse;width:100%">{rows}</table>', unsafe_allow_html=True)

            except requests.exceptions.SSLError as e:
                st.markdown(f'<div class="result-card danger">❌ SSL Error: {e}</div>', unsafe_allow_html=True)
            except Exception as e:
                st.markdown(f'<div class="result-card danger">❌ Error: {e}</div>', unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# MODULE 5 – PING & TRACEROUTE
# ══════════════════════════════════════════════════════════════════════════════
elif "Ping" in tool:
    st.markdown("# Ping & Traceroute")
    st.markdown('<p class="mono">ICMP reachability and network path analysis</p>', unsafe_allow_html=True)

    target = st.text_input("Target (IP or hostname)", placeholder="e.g. 8.8.8.8 or cloudflare.com")

    col1, col2 = st.columns(2)
    with col1:
        run_ping = st.button("▶  Ping", use_container_width=True)
    with col2:
        run_trace = st.button("▶  Traceroute", use_container_width=True)

    if run_ping and target:
        st.markdown("### Ping Results")
        try:
            result = subprocess.run(
                ["ping", "-c", "5", "-W", "2", target],
                capture_output=True, text=True, timeout=20
            )
            output = result.stdout + result.stderr
            lines = output.strip().split("\n")

            # Parse RTT stats
            rtt_line = next((l for l in lines if "rtt" in l or "round-trip" in l), None)
            loss_line = next((l for l in lines if "packet loss" in l), None)
            loss = "?%"
            if loss_line:
                import re
                m = re.search(r"(\d+\.?\d*)% packet loss", loss_line)
                if m:
                    loss = m.group(1) + "%"

            loss_color = "success" if loss == "0%" else ("warning" if float(loss.rstrip("%")) < 50 else "danger")

            st.markdown(f"""
            <div class="result-card {loss_color}">
                <span class="section-label">PACKET LOSS</span>
                <span class="val" style="font-size:1.4rem">{loss}</span>
            </div>
            """, unsafe_allow_html=True)

            if rtt_line:
                st.markdown(f"""
                <div class="result-card info">
                    <span class="section-label">RTT STATISTICS</span>
                    <span class="val">{rtt_line.strip()}</span>
                </div>
                """, unsafe_allow_html=True)

            with st.expander("📋  Full Ping Output"):
                st.code(output, language="text")

        except subprocess.TimeoutExpired:
            st.markdown('<div class="result-card danger">Ping timeout – host tidak merespons.</div>', unsafe_allow_html=True)
        except FileNotFoundError:
            st.markdown('<div class="result-card warning">⚠ `ping` command tidak tersedia di environment ini.</div>', unsafe_allow_html=True)
        except Exception as e:
            st.markdown(f'<div class="result-card danger">❌ Error: {e}</div>', unsafe_allow_html=True)

    if run_trace and target:
        st.markdown("### Traceroute")
        st.markdown('<p class="mono">Melacak jalur paket ke host tujuan…</p>', unsafe_allow_html=True)
        try:
            result = subprocess.run(
                ["traceroute", "-m", "20", "-w", "2", target],
                capture_output=True, text=True, timeout=60
            )
            output = result.stdout + result.stderr

            lines = output.strip().split("\n")
            st.markdown('<div class="result-card info"><span class="section-label">HOP ANALYSIS</span>', unsafe_allow_html=True)
            hop_rows = ""
            for line in lines[1:]:
                if line.strip():
                    hop_rows += f'<div class="mono" style="margin:2px 0">{line}</div>'
            st.markdown(f'{hop_rows}</div>', unsafe_allow_html=True)

        except subprocess.TimeoutExpired:
            st.markdown('<div class="result-card warning">⚠ Traceroute timeout – beberapa hop mungkin tidak merespons.</div>', unsafe_allow_html=True)
        except FileNotFoundError:
            st.markdown('<div class="result-card warning">⚠ `traceroute` tidak tersedia. Pastikan package diinstall.</div>', unsafe_allow_html=True)
        except Exception as e:
            st.markdown(f'<div class="result-card danger">❌ Error: {e}</div>', unsafe_allow_html=True)
