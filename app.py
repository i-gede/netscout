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
import re
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
html, body, [class*="css"] { font-family: 'IBM Plex Sans', sans-serif; }
.stApp { background-color: #0d1117; color: #c9d1d9; }
[data-testid="stSidebar"] { background-color: #161b22; border-right: 1px solid #21262d; }
[data-testid="stSidebar"] .stRadio label { color: #8b949e !important; font-family: 'IBM Plex Mono', monospace; font-size: 0.82rem; }
h1 { font-family: 'IBM Plex Mono', monospace !important; color: #58a6ff !important; letter-spacing: -0.5px; font-size: 1.6rem !important; }
h2, h3 { font-family: 'IBM Plex Mono', monospace !important; color: #79c0ff !important; font-size: 1.1rem !important; }
.result-card { background: #161b22; border: 1px solid #21262d; border-radius: 6px; padding: 1.2rem 1.4rem; margin-bottom: 0.8rem; font-family: 'IBM Plex Mono', monospace; font-size: 0.83rem; }
.result-card.success { border-left: 3px solid #3fb950; }
.result-card.danger  { border-left: 3px solid #f85149; }
.result-card.warning { border-left: 3px solid #d29922; }
.result-card.info    { border-left: 3px solid #58a6ff; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 20px; font-size: 0.72rem; font-family: 'IBM Plex Mono', monospace; font-weight: 600; margin-left: 6px; }
.badge-open    { background: #1a3a1a; color: #3fb950; border: 1px solid #238636; }
.badge-closed  { background: #3a1a1a; color: #f85149; border: 1px solid #6e2c2c; }
.badge-filtered{ background: #3a2a1a; color: #d29922; border: 1px solid #6e5228; }
.mono { font-family: 'IBM Plex Mono', monospace; font-size: 0.82rem; color: #8b949e; }
.val  { color: #79c0ff; font-weight: 500; }
.ok   { color: #3fb950; }
.err  { color: #f85149; }
.warn { color: #d29922; }
.section-label { font-family: 'IBM Plex Mono', monospace; font-size: 0.68rem; text-transform: uppercase; letter-spacing: 2px; color: #30363d; border-bottom: 1px solid #21262d; padding-bottom: 6px; margin-bottom: 12px; }
.stTextInput input, .stNumberInput input { background: #161b22 !important; border: 1px solid #30363d !important; color: #c9d1d9 !important; font-family: 'IBM Plex Mono', monospace !important; border-radius: 4px !important; }
.stButton > button { background: #21262d !important; color: #58a6ff !important; border: 1px solid #30363d !important; font-family: 'IBM Plex Mono', monospace !important; font-size: 0.82rem !important; border-radius: 4px !important; transition: all 0.15s; }
.stButton > button:hover { background: #30363d !important; border-color: #58a6ff !important; }
.streamlit-expanderHeader { font-family: 'IBM Plex Mono', monospace !important; background: #161b22 !important; border: 1px solid #21262d !important; color: #8b949e !important; font-size: 0.82rem !important; }
.disclaimer { background: #1c1a00; border: 1px solid #9e6a03; border-radius: 6px; padding: 0.8rem 1.2rem; font-size: 0.78rem; color: #e3b341; font-family: 'IBM Plex Mono', monospace; margin-bottom: 1.2rem; }
.stProgress > div > div { background: #1f6feb !important; }
[data-testid="stMetric"] { background: #161b22; border: 1px solid #21262d; border-radius: 6px; padding: 0.8rem 1rem; }
[data-testid="stMetricLabel"] { color: #8b949e !important; font-family: 'IBM Plex Mono', monospace !important; font-size: 0.72rem !important; }
[data-testid="stMetricValue"] { color: #58a6ff !important; font-family: 'IBM Plex Mono', monospace !important; }
.stDownloadButton > button { background: #0d2e15 !important; color: #3fb950 !important; border: 1px solid #238636 !important; font-family: 'IBM Plex Mono', monospace !important; font-size: 0.82rem !important; border-radius: 4px !important; }
</style>
""", unsafe_allow_html=True)

# ── Helpers ───────────────────────────────────────────────────────────────────
def resolve_host(host: str) -> str | None:
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None

def scan_port(host: str, port: int, timeout: float = 1.5) -> tuple[int, str, float]:
    start = time.time()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
    latency = round((time.time() - start) * 1000, 1)
    status = "open" if result == 0 else "closed"
    return port, status, latency

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 587: "SMTP-TLS", 993: "IMAPS",
    995: "POP3S", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "Jupyter", 9200: "Elasticsearch", 27017: "MongoDB",
}

# VPN/PAM/Jumphost well-known ports
VPN_PROFILES = {
    "OpenVPN (UDP)":     {"port": 1194, "protocol": "UDP", "desc": "Standard OpenVPN port"},
    "OpenVPN (TCP)":     {"port": 443,  "protocol": "TCP", "desc": "OpenVPN over TCP/443"},
    "WireGuard":         {"port": 51820,"protocol": "UDP", "desc": "WireGuard VPN"},
    "IPSec IKE":         {"port": 500,  "protocol": "UDP", "desc": "IPSec key exchange"},
    "IPSec NAT-T":       {"port": 4500, "protocol": "UDP", "desc": "IPSec NAT traversal"},
    "SSL VPN (F5/Pulse)":{"port": 443,  "protocol": "TCP", "desc": "SSL VPN gateway"},
    "Cisco AnyConnect":  {"port": 443,  "protocol": "TCP", "desc": "Cisco SSL VPN"},
    "PPTP":              {"port": 1723, "protocol": "TCP", "desc": "PPTP VPN (legacy)"},
    "L2TP":              {"port": 1701, "protocol": "UDP", "desc": "L2TP VPN"},
    "SSH Jumphost":      {"port": 22,   "protocol": "TCP", "desc": "SSH Jumphost / Bastion"},
    "PAM SSH Proxy":     {"port": 2222, "protocol": "TCP", "desc": "PAM SSH alternate port"},
    "PAM RDP Proxy":     {"port": 3389, "protocol": "TCP", "desc": "PAM RDP gateway"},
    "PAM Web Portal":    {"port": 443,  "protocol": "TCP", "desc": "PAM web console"},
    "PAM Web Alt":       {"port": 8443, "protocol": "TCP", "desc": "PAM web console (alt)"},
    "RDP Gateway":       {"port": 3391, "protocol": "UDP", "desc": "RDP UDP transport"},
    "RADIUS Auth":       {"port": 1812, "protocol": "UDP", "desc": "RADIUS authentication"},
    "LDAP":              {"port": 389,  "protocol": "TCP", "desc": "Directory services"},
    "LDAPS":             {"port": 636,  "protocol": "TCP", "desc": "LDAP over SSL"},
}

def check_tcp_port(host: str, port: int, timeout: float = 3.0) -> tuple[str, float]:
    start = time.time()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency = round((time.time() - start) * 1000, 1)
            return "open", latency
    except socket.timeout:
        return "filtered", round((time.time() - start) * 1000, 1)
    except ConnectionRefusedError:
        return "closed", round((time.time() - start) * 1000, 1)
    except Exception as e:
        return f"error: {str(e)[:30]}", round((time.time() - start) * 1000, 1)

def check_udp_port(host: str, port: int, timeout: float = 3.0) -> tuple[str, str]:
    """UDP is connectionless — we can only infer reachability via ICMP response."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"\x00" * 8, (host, port))
        try:
            sock.recvfrom(1024)
            return "open", "Response received"
        except socket.timeout:
            return "open|filtered", "No response (normal for UDP)"
    except Exception as e:
        return "error", str(e)[:40]
    finally:
        sock.close()

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛰️ NetScout")
    st.markdown('<p class="mono">Network Analysis Tool v2.0</p>', unsafe_allow_html=True)
    st.markdown("---")
    tool = st.radio(
        "SELECT MODULE",
        options=[
            "🔍  Port Scanner",
            "🌐  DNS & WHOIS",
            "🔒  SSL Certificate",
            "📋  HTTP Headers",
            "📡  Ping & Traceroute",
            "🔐  VPN / PAM / Jumphost",
        ],
    )
    st.markdown("---")
    st.markdown("""
    <div style="font-family:'IBM Plex Mono',monospace;font-size:0.7rem;color:#30363d;line-height:1.8">
    ⚠ Untuk penggunaan pada<br>sistem yang Anda miliki<br>atau memiliki izin resmi.<br><br>
    Unauthorized scanning<br>adalah tindakan ilegal.
    </div>""", unsafe_allow_html=True)

# ── Disclaimer ────────────────────────────────────────────────────────────────
st.markdown("""
<div class="disclaimer">
⚠️  <strong>DISCLAIMER</strong> — Tool ini hanya boleh digunakan pada sistem/jaringan yang Anda miliki
atau memiliki izin tertulis untuk melakukan pengujian. Penggunaan tanpa izin adalah <strong>tindakan ilegal</strong>.
</div>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# MODULE 1 – PORT SCANNER
# ══════════════════════════════════════════════════════════════════════════════
if "Port Scanner" in tool:
    st.markdown("# Port Scanner")
    st.markdown('<p class="mono">Scan open TCP ports on a target host</p>', unsafe_allow_html=True)
    col1, col2 = st.columns([3, 1])
    with col1:
        target = st.text_input("Target (IP or hostname)", placeholder="e.g. 192.168.1.1")
    with col2:
        scan_mode = st.selectbox("Mode", ["Common Ports", "Custom Range"])
    if scan_mode == "Custom Range":
        c1, c2 = st.columns(2)
        with c1: port_start = st.number_input("Start Port", min_value=1, max_value=65534, value=1)
        with c2: port_end   = st.number_input("End Port",   min_value=2, max_value=65535, value=1024)
        ports_to_scan = list(range(int(port_start), int(port_end)+1))
    else:
        ports_to_scan = list(COMMON_PORTS.keys())
    col_btn, col_threads = st.columns([2, 1])
    with col_btn:    run_scan = st.button("▶  Run Port Scan", use_container_width=True)
    with col_threads: threads = st.number_input("Threads", min_value=10, max_value=200, value=50, step=10)
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
                        port, status, lat = future.result()
                        results.append((port, status, lat))
                        done += 1
                        progress.progress(done/total, text=f"Scanned {done}/{total} ports…")
                progress.empty()
                results.sort(key=lambda x: x[0])
                open_ports = [(p, s, l) for p, s, l in results if s == "open"]
                m1, m2, m3 = st.columns(3)
                m1.metric("Total Scanned", total)
                m2.metric("Open Ports", len(open_ports))
                m3.metric("Closed/Filtered", total - len(open_ports))
                st.markdown("---")
                if open_ports:
                    st.markdown("### Open Ports")
                    for port, status, lat in open_ports:
                        service = COMMON_PORTS.get(port, "unknown")
                        st.markdown(f"""
                        <div class="result-card success">
                            <span class="val">{port}</span>/tcp
                            <span class="badge badge-open">OPEN</span>
                            <span class="mono" style="margin-left:12px">service: <span class="val">{service}</span></span>
                            <span class="mono" style="margin-left:12px">latency: <span class="val">{lat}ms</span></span>
                        </div>""", unsafe_allow_html=True)
                else:
                    st.markdown('<div class="result-card warning">Tidak ada port terbuka yang ditemukan.</div>', unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# MODULE 2 – DNS & WHOIS
# ══════════════════════════════════════════════════════════════════════════════
elif "DNS" in tool:
    st.markdown("# DNS & WHOIS Lookup")
    target = st.text_input("Domain", placeholder="e.g. google.com")
    col1, col2 = st.columns(2)
    with col1: run_dns   = st.button("▶  DNS Lookup",   use_container_width=True)
    with col2: run_whois = st.button("▶  WHOIS Lookup", use_container_width=True)
    if run_dns and target:
        st.markdown("### DNS Records")
        resolver = dns.resolver.Resolver(); resolver.timeout = 5; resolver.lifetime = 8
        for rtype in ["A","AAAA","MX","NS","TXT","CNAME","SOA"]:
            try:
                answers = resolver.resolve(target, rtype)
                records = [str(r) for r in answers]
                st.markdown(f"""<div class="result-card info">
                    <span class="section-label">{rtype}</span><br>
                    {'<br>'.join(f'<span class="val">{r}</span>' for r in records)}
                </div>""", unsafe_allow_html=True)
            except: pass
        try:
            ip = socket.gethostbyname(target)
            rev = socket.gethostbyaddr(ip)
            st.markdown(f"""<div class="result-card info">
                <span class="section-label">REVERSE DNS</span><br>
                <span class="mono">IP: <span class="val">{ip}</span></span><br>
                <span class="mono">PTR: <span class="val">{rev[0]}</span></span>
            </div>""", unsafe_allow_html=True)
        except: pass
    if run_whois and target:
        st.markdown("### WHOIS Information")
        try:
            w = whois.whois(target)
            fields = {"Registrar": w.registrar, "Creation Date": str(w.creation_date),
                      "Expiration Date": str(w.expiration_date), "Name Servers": w.name_servers,
                      "Status": w.status, "Country": w.country, "Org": w.org}
            rows = ""
            for k, v in fields.items():
                if v:
                    val = ", ".join(v) if isinstance(v, list) else str(v)
                    rows += f'<tr><td class="mono" style="padding:4px 12px 4px 0;color:#8b949e">{k}</td><td class="mono val">{val[:120]}</td></tr>'
            st.markdown(f'<div class="result-card info"><span class="section-label">WHOIS – {target}</span><table style="border-collapse:collapse;width:100%">{rows}</table></div>', unsafe_allow_html=True)
        except Exception as e:
            st.markdown(f'<div class="result-card danger">WHOIS lookup gagal: {e}</div>', unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# MODULE 3 – SSL
# ══════════════════════════════════════════════════════════════════════════════
elif "SSL" in tool:
    st.markdown("# SSL/TLS Certificate Checker")
    col1, col2 = st.columns([3,1])
    with col1: target = st.text_input("Hostname", placeholder="e.g. github.com")
    with col2: port   = st.number_input("Port", value=443, min_value=1, max_value=65535)
    if st.button("▶  Check Certificate", use_container_width=True):
        if not target: st.error("Masukkan hostname.")
        else:
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((target, int(port)), timeout=8) as sock:
                    with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                        cert = ssock.getpeercert(); cipher = ssock.cipher(); proto = ssock.version()
                not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                not_after  = datetime.strptime(cert["notAfter"],  "%b %d %H:%M:%S %Y %Z")
                days_left  = (not_after - datetime.utcnow()).days
                valid_status = "success" if days_left > 30 else ("warning" if days_left > 0 else "danger")
                subject = dict(x[0] for x in cert.get("subject",[]))
                issuer  = dict(x[0] for x in cert.get("issuer",[]))
                san_list= [v for k,v in cert.get("subjectAltName",[]) if k=="DNS"]
                st.markdown(f"""<div class="result-card {valid_status}">
                    <span class="section-label">VALIDITY</span>
                    <span class="mono">Not Before: <span class="val">{not_before.strftime('%Y-%m-%d')}</span></span><br>
                    <span class="mono">Not After:  <span class="val">{not_after.strftime('%Y-%m-%d')}</span></span><br>
                    <span class="mono">Days Left:  <span class="{'ok' if days_left>30 else ('warn' if days_left>0 else 'err')}">{days_left} days</span></span>
                </div>""", unsafe_allow_html=True)
                st.markdown(f"""<div class="result-card info">
                    <span class="section-label">CIPHER &amp; PROTOCOL</span>
                    <span class="mono">Protocol: <span class="val">{proto}</span></span><br>
                    <span class="mono">Cipher:   <span class="val">{cipher[0]}</span></span>
                </div>""", unsafe_allow_html=True)
            except Exception as e:
                st.markdown(f'<div class="result-card danger">❌ Error: {e}</div>', unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# MODULE 4 – HTTP HEADERS
# ══════════════════════════════════════════════════════════════════════════════
elif "HTTP" in tool:
    st.markdown("# HTTP Headers Analyzer")
    col1, col2 = st.columns([3,1])
    with col1: target = st.text_input("URL", placeholder="e.g. https://example.com")
    with col2: method = st.selectbox("Method", ["GET","HEAD"])
    follow_redirects = st.checkbox("Follow redirects", value=True)
    if st.button("▶  Analyze Headers", use_container_width=True):
        if not target: st.error("Masukkan URL.")
        else:
            url = target if target.startswith("http") else f"https://{target}"
            try:
                r = requests.request(method, url, allow_redirects=follow_redirects, timeout=10,
                                     headers={"User-Agent": "NetScout/2.0"})
                status_color = "success" if r.status_code < 400 else "danger"
                st.markdown(f"""<div class="result-card {status_color}">
                    <span class="section-label">RESPONSE</span>
                    <span class="mono">Status: <span class="val">{r.status_code} {r.reason}</span></span>
                </div>""", unsafe_allow_html=True)
                SECURITY_HEADERS = {
                    "Strict-Transport-Security": "HSTS",
                    "Content-Security-Policy":   "CSP",
                    "X-Frame-Options":           "Clickjacking Protection",
                    "X-Content-Type-Options":    "MIME Sniffing Protection",
                    "Referrer-Policy":           "Referrer Policy",
                    "Permissions-Policy":        "Permissions Policy",
                    "X-XSS-Protection":          "XSS Protection",
                }
                st.markdown("### Security Headers")
                for hdr, label in SECURITY_HEADERS.items():
                    val = r.headers.get(hdr)
                    if val:
                        st.markdown(f"""<div class="result-card success">
                            <span class="mono ok">✔ {label}</span><span class="badge badge-open">PRESENT</span><br>
                            <span class="mono" style="color:#484f58">{hdr}: <span style="color:#8b949e">{val[:100]}</span></span>
                        </div>""", unsafe_allow_html=True)
                    else:
                        st.markdown(f"""<div class="result-card danger">
                            <span class="mono err">✖ {label}</span><span class="badge badge-closed">MISSING</span>
                        </div>""", unsafe_allow_html=True)
                with st.expander("📋  All Response Headers"):
                    rows = "".join(f'<tr><td class="mono" style="padding:3px 14px 3px 0;color:#8b949e">{k}</td><td class="mono val">{v}</td></tr>'
                                   for k,v in sorted(r.headers.items()))
                    st.markdown(f'<table style="border-collapse:collapse;width:100%">{rows}</table>', unsafe_allow_html=True)
            except Exception as e:
                st.markdown(f'<div class="result-card danger">❌ Error: {e}</div>', unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# MODULE 5 – PING & TRACEROUTE  (with PDF report)
# ══════════════════════════════════════════════════════════════════════════════
elif "Ping" in tool:
    st.markdown("# Ping & Traceroute")
    st.markdown('<p class="mono">ICMP reachability, path analysis, and downloadable PDF report</p>', unsafe_allow_html=True)

    target = st.text_input("Target (IP or hostname)", placeholder="e.g. 8.8.8.8")

    col1, col2, col3 = st.columns(3)
    with col1: run_ping  = st.button("▶  Ping",       use_container_width=True)
    with col2: run_trace = st.button("▶  Traceroute", use_container_width=True)
    with col3: run_both  = st.button("▶  Both + PDF Report", use_container_width=True)

    ping_output  = None
    trace_output = None
    ping_stats   = {}
    ip           = None

    def do_ping(target):
        result = subprocess.run(["ping","-c","5","-W","2", target],
                                capture_output=True, text=True, timeout=20)
        return result.stdout + result.stderr

    def do_trace(target):
        result = subprocess.run(["traceroute","-m","20","-w","2", target],
                                capture_output=True, text=True, timeout=60)
        return result.stdout + result.stderr

    def parse_ping_stats(output: str) -> dict:
        stats = {}
        loss_m = re.search(r"(\d+\.?\d*)% packet loss", output)
        rtt_m  = re.search(r"rtt.+?=\s*([\d.]+)/([\d.]+)/([\d.]+)", output)
        if loss_m: stats["loss"] = loss_m.group(1) + "%"
        if rtt_m:
            stats["rtt_min"] = rtt_m.group(1) + " ms"
            stats["rtt_avg"] = rtt_m.group(2) + " ms"
            stats["rtt_max"] = rtt_m.group(3) + " ms"
        return stats

    if run_ping and target:
        ip = resolve_host(target)
        st.markdown("### Ping Results")
        try:
            ping_output = do_ping(target)
            ping_stats  = parse_ping_stats(ping_output)
            loss = ping_stats.get("loss","?%")
            lv   = float(loss.rstrip("%")) if loss != "?%" else 100
            color = "success" if lv == 0 else ("warning" if lv < 50 else "danger")
            m1, m2, m3 = st.columns(3)
            m1.metric("Packet Loss", loss)
            m2.metric("Avg RTT",  ping_stats.get("rtt_avg","—"))
            m3.metric("Max RTT",  ping_stats.get("rtt_max","—"))
            with st.expander("📋  Full Ping Output"):
                st.code(ping_output, language="text")
        except Exception as e:
            st.markdown(f'<div class="result-card danger">❌ {e}</div>', unsafe_allow_html=True)

    if run_trace and target:
        ip = resolve_host(target)
        st.markdown("### Traceroute")
        try:
            trace_output = do_trace(target)
            lines = trace_output.strip().split("\n")
            hop_rows = "".join(f'<div class="mono" style="margin:2px 0">{l}</div>' for l in lines[1:] if l.strip())
            st.markdown(f'<div class="result-card info"><span class="section-label">HOP ANALYSIS</span>{hop_rows}</div>', unsafe_allow_html=True)
        except Exception as e:
            st.markdown(f'<div class="result-card danger">❌ {e}</div>', unsafe_allow_html=True)

    if run_both and target:
        ip = resolve_host(target) or target
        st.markdown("### Running Ping + Traceroute…")
        col_p, col_t = st.columns(2)
        with col_p:
            with st.spinner("Pinging…"):
                try:    ping_output = do_ping(target)
                except: ping_output = "ping failed"
            ping_stats = parse_ping_stats(ping_output)
            loss = ping_stats.get("loss","?%")
            lv   = float(loss.rstrip("%")) if loss != "?%" else 100
            color = "success" if lv == 0 else ("warning" if lv < 50 else "danger")
            st.markdown(f'<div class="result-card {color}"><span class="section-label">PING</span>'
                        f'<span class="mono">Loss: <span class="val">{loss}</span></span><br>'
                        f'<span class="mono">Avg RTT: <span class="val">{ping_stats.get("rtt_avg","—")}</span></span></div>',
                        unsafe_allow_html=True)
        with col_t:
            with st.spinner("Tracing route…"):
                try:    trace_output = do_trace(target)
                except: trace_output = "traceroute failed"
            hops = [l for l in trace_output.split("\n")[1:] if l.strip()]
            st.markdown(f'<div class="result-card info"><span class="section-label">TRACEROUTE</span>'
                        f'<span class="mono">{len(hops)} hops recorded</span></div>',
                        unsafe_allow_html=True)

        # ── Generate PDF ───────────────────────────────────────────────────
        st.markdown("---")
        st.markdown("### 📄 Download PDF Report")
        try:
            from report_generator import generate_ping_report
            pdf_bytes = generate_ping_report(
                target=target,
                ip=ip or target,
                ping_output=ping_output or "",
                trace_output=trace_output or "",
                ping_stats=ping_stats,
            )
            fname = f"netscout_ping_{target.replace('.','_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
            st.download_button(
                label="⬇  Download Diagnostic Report (PDF)",
                data=pdf_bytes,
                file_name=fname,
                mime="application/pdf",
                use_container_width=True,
            )
            st.markdown('<p class="mono ok">✔ PDF report siap didownload</p>', unsafe_allow_html=True)
        except Exception as e:
            st.markdown(f'<div class="result-card warning">⚠ PDF generation gagal: {e}</div>', unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# MODULE 6 – VPN / PAM / JUMPHOST
# ══════════════════════════════════════════════════════════════════════════════
elif "VPN" in tool:
    st.markdown("# VPN / PAM / Jumphost Checker")
    st.markdown('<p class="mono">Diagnosa konektivitas endpoint VPN, PAM, dan Jumphost yang dilaporkan bermasalah oleh tenant</p>', unsafe_allow_html=True)

    st.markdown("""
    <div class="result-card info">
        <span class="section-label">CARA PENGGUNAAN</span>
        <span class="mono">Tool ini memverifikasi apakah <span class="val">port/endpoint</span> VPN, PAM, atau Jumphost
        <span class="val">dapat dijangkau</span> dari server ini.<br>
        Jika port terbuka tapi tenant tetap tidak bisa login → masalah ada di <span class="warn">layer autentikasi</span>
        (credentials, MFA, sertifikat), bukan jaringan.<br>
        Jika port tertutup/filtered → masalah ada di <span class="err">jaringan/firewall</span>.</span>
    </div>""", unsafe_allow_html=True)

    col1, col2 = st.columns([3, 1])
    with col1:
        target = st.text_input("Target Host / IP VPN-PAM-Jumphost", placeholder="e.g. vpn.company.com atau 203.0.113.10")
    with col2:
        check_mode = st.selectbox("Mode", ["Preset Profile", "Custom Ports"])

    if check_mode == "Preset Profile":
        profile_options = list(VPN_PROFILES.keys())
        selected_services = st.multiselect(
            "Pilih service yang ingin dicek",
            options=profile_options,
            default=["SSH Jumphost", "PAM SSH Proxy", "PAM Web Portal", "Cisco AnyConnect"],
            help="Pilih semua service yang relevan dengan infrastruktur Anda"
        )
        services_to_check = {k: VPN_PROFILES[k] for k in selected_services}
    else:
        st.markdown('<p class="mono">Masukkan port custom (pisahkan dengan koma):</p>', unsafe_allow_html=True)
        custom_ports_input = st.text_input("Ports", placeholder="22, 443, 1194, 3389")
        custom_name_input  = st.text_input("Label (opsional)", placeholder="SSH, HTTPS, OpenVPN, RDP")
        services_to_check = {}
        if custom_ports_input:
            ports = [p.strip() for p in custom_ports_input.split(",") if p.strip().isdigit()]
            names = [n.strip() for n in custom_name_input.split(",")] if custom_name_input else []
            for i, p in enumerate(ports):
                label = names[i] if i < len(names) else f"Port {p}"
                services_to_check[label] = {"port": int(p), "protocol": "TCP", "desc": ""}

    notes_input = st.text_area("Catatan Insiden (opsional)",
                                placeholder="Contoh: Tenant PT. XYZ melaporkan tidak bisa login VPN sejak pukul 09.00 WIB...",
                                height=80)

    col_btn1, col_btn2 = st.columns(2)
    with col_btn1: run_check = st.button("▶  Run Connectivity Check", use_container_width=True)
    with col_btn2: timeout   = st.number_input("Timeout (detik)", min_value=1, max_value=10, value=3)

    if run_check:
        if not target:
            st.error("Masukkan target host/IP terlebih dahulu.")
        elif not services_to_check:
            st.error("Pilih minimal satu service untuk dicek.")
        else:
            ip = resolve_host(target)
            if not ip:
                st.markdown(f'<div class="result-card danger">❌ Tidak bisa resolve hostname: <span class="val">{target}</span><br>'
                            f'<span class="mono">Pastikan DNS bisa menjangkau host ini, atau gunakan IP langsung.</span></div>',
                            unsafe_allow_html=True)
            else:
                st.markdown(f'<p class="mono">Resolved <span class="val">{target}</span> → <span class="val">{ip}</span></p>',
                            unsafe_allow_html=True)

                progress = st.progress(0, text="Checking endpoints…")
                check_results = []
                total = len(services_to_check)

                for i, (svc_name, svc_info) in enumerate(services_to_check.items()):
                    progress.progress((i+1)/total, text=f"Checking {svc_name}…")
                    port     = svc_info["port"]
                    protocol = svc_info.get("protocol", "TCP")
                    desc     = svc_info.get("desc", "")

                    if protocol == "UDP":
                        status, detail = check_udp_port(ip, port, float(timeout))
                        latency_str = "—"
                    else:
                        status, latency = check_tcp_port(ip, port, float(timeout))
                        latency_str = f"{latency} ms"
                        detail = desc

                    check_results.append({
                        "service":  svc_name,
                        "port":     port,
                        "protocol": protocol,
                        "status":   status,
                        "latency":  latency_str,
                        "detail":   detail,
                    })

                progress.empty()

                # ── Summary metrics ─────────────────────────────────────────
                open_count     = sum(1 for r in check_results if "open" in r["status"].lower() and "filtered" not in r["status"].lower())
                filtered_count = sum(1 for r in check_results if "filtered" in r["status"].lower())
                closed_count   = sum(1 for r in check_results if "closed" in r["status"].lower() or "error" in r["status"].lower())

                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Total Checked", total)
                m2.metric("Reachable", open_count)
                m3.metric("Filtered/Unknown", filtered_count)
                m4.metric("Closed/Error", closed_count)

                # ── Overall status ──────────────────────────────────────────
                if open_count == total:
                    overall = "REACHABLE"
                    ov_color = "success"
                    ov_msg   = "Semua endpoint dapat dijangkau. Jika tenant tetap tidak bisa login, masalah ada di layer autentikasi (credentials/MFA/sertifikat)."
                elif open_count > 0:
                    overall = "PARTIAL"
                    ov_color = "warning"
                    ov_msg   = f"Sebagian endpoint tidak dapat dijangkau. Cek firewall rule atau routing untuk service yang tertutup."
                else:
                    overall = "UNREACHABLE"
                    ov_color = "danger"
                    ov_msg   = "Tidak ada endpoint yang bisa dijangkau. Kemungkinan firewall memblokir semua traffic, host down, atau routing bermasalah."

                st.markdown(f'<div class="result-card {ov_color}"><span class="section-label">OVERALL STATUS</span>'
                            f'<span class="val">{overall}</span><br><span class="mono">{ov_msg}</span></div>',
                            unsafe_allow_html=True)

                # ── Per-service results ─────────────────────────────────────
                st.markdown("### Per-Service Results")
                for r in check_results:
                    status  = r["status"]
                    is_open = "open" in status.lower() and "filtered" not in status.lower()
                    is_filt = "filtered" in status.lower()
                    card_cls = "success" if is_open else ("warning" if is_filt else "danger")
                    badge    = ("badge-open" if is_open else ("badge-filtered" if is_filt else "badge-closed"))
                    badge_lbl= ("OPEN" if is_open else ("FILTERED" if is_filt else "CLOSED"))
                    proto_icon = "🔒" if r["protocol"] == "UDP" else "🔗"

                    st.markdown(f"""
                    <div class="result-card {card_cls}">
                        <span class="val">{r['service']}</span>
                        <span class="badge {badge}">{badge_lbl}</span>
                        <span class="mono" style="margin-left:10px">{proto_icon} {r['protocol']} :{r['port']}</span>
                        <span class="mono" style="margin-left:10px">latency: <span class="val">{r['latency']}</span></span>
                        <br><span class="mono" style="color:#484f58">{r['detail']}</span>
                    </div>""", unsafe_allow_html=True)

                # ── Diagnosis Recommendation ────────────────────────────────
                st.markdown("### Rekomendasi Diagnosis")
                if closed_count > 0:
                    closed_svcs = [r["service"] for r in check_results if "closed" in r["status"].lower() or "error" in r["status"].lower()]
                    st.markdown(f"""<div class="result-card danger">
                        <span class="section-label">PORT TERTUTUP — KEMUNGKINAN PENYEBAB</span>
                        <span class="mono">Service: <span class="err">{", ".join(closed_svcs)}</span></span><br>
                        <span class="mono">1. Firewall/Security Group memblokir port ini dari source IP Anda</span><br>
                        <span class="mono">2. Service tidak berjalan di server target</span><br>
                        <span class="mono">3. IP target salah atau host sudah berubah</span><br>
                        <span class="mono">→ <span class="warn">Cek firewall rule dan pastikan service berjalan</span></span>
                    </div>""", unsafe_allow_html=True)

                if open_count > 0 and (closed_count > 0 or filtered_count > 0):
                    st.markdown(f"""<div class="result-card warning">
                        <span class="section-label">MIXED RESULT — PARTIAL CONNECTIVITY</span>
                        <span class="mono">Beberapa port terbuka, beberapa tidak.<br>
                        → Kemungkinan ada <span class="warn">firewall rule yang selektif</span> memblokir port tertentu.<br>
                        → Minta tenant coba service yang port-nya <span class="ok">OPEN</span> dulu untuk isolasi masalah.</span>
                    </div>""", unsafe_allow_html=True)

                if open_count == total:
                    st.markdown(f"""<div class="result-card success">
                        <span class="section-label">SEMUA PORT OPEN — CEK AUTENTIKASI</span>
                        <span class="mono">Konektivitas jaringan <span class="ok">OK</span>. Jika tenant masih tidak bisa login:<br>
                        1. Cek <span class="warn">credentials</span> — username/password salah atau expired<br>
                        2. Cek <span class="warn">MFA/OTP</span> — token expired atau tidak tersync<br>
                        3. Cek <span class="warn">sertifikat klien</span> — expired atau tidak dipercaya<br>
                        4. Cek <span class="warn">account lock</span> — terlalu banyak percobaan gagal<br>
                        5. Cek <span class="warn">IP whitelist</span> — IP tenant mungkin tidak diizinkan</span>
                    </div>""", unsafe_allow_html=True)

                # ── PDF Report ──────────────────────────────────────────────
                st.markdown("---")
                st.markdown("### 📄 Download PDF Report")
                try:
                    from report_generator import generate_vpn_report
                    pdf_bytes = generate_vpn_report(
                        target=target,
                        ip=ip,
                        check_results=check_results,
                        overall=overall,
                        notes=notes_input,
                    )
                    fname = f"netscout_vpn_{target.replace('.','_')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"
                    st.download_button(
                        label="⬇  Download Diagnostic Report (PDF)",
                        data=pdf_bytes,
                        file_name=fname,
                        mime="application/pdf",
                        use_container_width=True,
                    )
                    st.markdown('<p class="mono ok">✔ PDF report siap didownload</p>', unsafe_allow_html=True)
                except Exception as e:
                    st.markdown(f'<div class="result-card warning">⚠ PDF generation gagal: {e}</div>', unsafe_allow_html=True)
