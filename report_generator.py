"""
report_generator.py — Generates PDF diagnostic reports for NetScout
"""
import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, KeepTogether
)

# ── Color palette (terminal dark theme adapted for print) ───────────────────
C_BG        = colors.HexColor("#0d1117")
C_PANEL     = colors.HexColor("#161b22")
C_BORDER    = colors.HexColor("#21262d")
C_BLUE      = colors.HexColor("#58a6ff")
C_GREEN     = colors.HexColor("#3fb950")
C_RED       = colors.HexColor("#f85149")
C_YELLOW    = colors.HexColor("#d29922")
C_TEXT      = colors.HexColor("#c9d1d9")
C_MUTED     = colors.HexColor("#8b949e")
C_WHITE     = colors.white
C_BLACK     = colors.HexColor("#0d1117")

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm


def _styles():
    base = getSampleStyleSheet()

    def ps(name, **kw):
        return ParagraphStyle(name, **kw)

    return {
        "title": ps("RPT_title",
            fontName="Helvetica-Bold", fontSize=20,
            textColor=C_BLUE, spaceAfter=2, leading=24),
        "subtitle": ps("RPT_sub",
            fontName="Helvetica", fontSize=9,
            textColor=C_MUTED, spaceAfter=10, leading=13),
        "section": ps("RPT_section",
            fontName="Helvetica-Bold", fontSize=11,
            textColor=C_BLUE, spaceBefore=14, spaceAfter=4, leading=14),
        "label": ps("RPT_label",
            fontName="Helvetica-Bold", fontSize=8,
            textColor=C_MUTED, spaceAfter=1, leading=10),
        "value": ps("RPT_value",
            fontName="Helvetica", fontSize=9,
            textColor=C_TEXT, spaceAfter=2, leading=12),
        "mono": ps("RPT_mono",
            fontName="Courier", fontSize=8,
            textColor=C_TEXT, spaceAfter=1, leading=11),
        "mono_muted": ps("RPT_mono_m",
            fontName="Courier", fontSize=7.5,
            textColor=C_MUTED, spaceAfter=1, leading=10),
        "ok": ps("RPT_ok",
            fontName="Helvetica-Bold", fontSize=8,
            textColor=C_GREEN, spaceAfter=1, leading=10),
        "warn": ps("RPT_warn",
            fontName="Helvetica-Bold", fontSize=8,
            textColor=C_YELLOW, spaceAfter=1, leading=10),
        "err": ps("RPT_err",
            fontName="Helvetica-Bold", fontSize=8,
            textColor=C_RED, spaceAfter=1, leading=10),
        "footer": ps("RPT_footer",
            fontName="Helvetica", fontSize=7,
            textColor=C_MUTED, alignment=TA_CENTER, leading=10),
    }


def _header_table(target: str, ip: str, timestamp: str, report_type: str, styles: dict):
    data = [[
        Paragraph(f"NetScout Diagnostic Report", styles["title"]),
        Paragraph(f"{report_type}<br/><font color='#8b949e'>{timestamp}</font>",
                  ParagraphStyle("rh", fontName="Helvetica", fontSize=9,
                                 textColor=C_BLUE, alignment=TA_RIGHT, leading=13)),
    ]]
    t = Table(data, colWidths=[PAGE_W - 2*MARGIN - 60*mm, 60*mm])
    t.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "BOTTOM"),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    return t


def _kv_table(rows: list[tuple], styles: dict, col_w=(50*mm, None)):
    """Render a list of (key, value, status) rows as a styled table."""
    usable = PAGE_W - 2*MARGIN
    cw0 = col_w[0]
    cw1 = usable - cw0
    data = []
    for key, val, status in rows:
        st = {"ok": styles["ok"], "warn": styles["warn"],
              "err": styles["err"]}.get(status, styles["value"])
        data.append([
            Paragraph(key, styles["label"]),
            Paragraph(str(val), st),
        ])
    t = Table(data, colWidths=[cw0, cw1])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_PANEL),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [C_PANEL, colors.HexColor("#1a1f27")]),
        ("TEXTCOLOR", (0,0), (-1,-1), C_TEXT),
        ("FONTSIZE", (0,0), (-1,-1), 8),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("RIGHTPADDING", (0,0), (-1,-1), 8),
        ("LINEBELOW", (0,0), (-1,-2), 0.3, C_BORDER),
        ("ROUNDEDCORNERS", [4, 4, 4, 4]),
    ]))
    return t


def _section_divider(label: str, styles: dict):
    return [
        Spacer(1, 6),
        Paragraph(label, styles["section"]),
        HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=4),
    ]


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(C_MUTED)
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    canvas.drawCentredString(PAGE_W/2, 10*mm,
        f"NetScout Diagnostic Report  •  Generated {ts}  •  For authorized use only")
    canvas.setStrokeColor(C_BORDER)
    canvas.setLineWidth(0.3)
    canvas.line(MARGIN, 13*mm, PAGE_W - MARGIN, 13*mm)
    canvas.restoreState()


# ════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ════════════════════════════════════════════════════════════════════════════

def generate_ping_report(target: str, ip: str, ping_output: str,
                          trace_output: str = None,
                          ping_stats: dict = None) -> bytes:
    """
    Generate a PDF report for Ping + Traceroute results.
    Returns bytes of the PDF.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN, bottomMargin=20*mm,
    )
    styles = _styles()
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    story = []

    # ── Header ──────────────────────────────────────────────────────────────
    story.append(_header_table(target, ip, ts, "Ping & Traceroute", styles))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BLUE, spaceAfter=8))

    # ── Target Info ─────────────────────────────────────────────────────────
    story += _section_divider("Target Information", styles)
    loss = ping_stats.get("loss", "N/A") if ping_stats else "N/A"
    loss_val = float(loss.replace("%","")) if loss != "N/A" else 100
    loss_status = "ok" if loss_val == 0 else ("warn" if loss_val < 50 else "err")
    rtt_avg = ping_stats.get("rtt_avg", "N/A") if ping_stats else "N/A"

    story.append(_kv_table([
        ("Target Host",  target, "value"),
        ("Resolved IP",  ip,     "value"),
        ("Timestamp",    ts,     "value"),
        ("Packet Loss",  loss,   loss_status),
        ("Avg RTT",      rtt_avg, "value"),
    ], styles))

    # ── Ping Output ─────────────────────────────────────────────────────────
    story += _section_divider("Ping Raw Output", styles)
    lines = ping_output.strip().split("\n") if ping_output else ["(no output)"]
    ping_block = []
    for line in lines:
        ping_block.append(Paragraph(line or " ", styles["mono"]))
    bg_table = Table([[ping_block]], colWidths=[PAGE_W - 2*MARGIN])
    bg_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), C_PANEL),
        ("TOPPADDING", (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("LEFTPADDING", (0,0), (-1,-1), 10),
        ("RIGHTPADDING", (0,0), (-1,-1), 10),
        ("LINEBELOW", (0,0), (-1,-1), 0.3, C_BORDER),
    ]))
    story.append(bg_table)

    # ── Traceroute ───────────────────────────────────────────────────────────
    if trace_output:
        story += _section_divider("Traceroute – Hop Analysis", styles)
        trace_lines = trace_output.strip().split("\n")
        hop_data = [["Hop", "Details"]]
        for line in trace_lines[1:]:
            if line.strip():
                parts = line.strip().split(None, 1)
                hop_num = parts[0] if parts else ""
                details = parts[1] if len(parts) > 1 else ""
                hop_data.append([hop_num, details])

        if len(hop_data) > 1:
            t = Table(hop_data, colWidths=[15*mm, PAGE_W - 2*MARGIN - 15*mm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,0), C_BORDER),
                ("TEXTCOLOR", (0,0), (-1,0), C_BLUE),
                ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE", (0,0), (-1,-1), 8),
                ("FONTNAME", (0,1), (-1,-1), "Courier"),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_PANEL, colors.HexColor("#1a1f27")]),
                ("TEXTCOLOR", (0,1), (-1,-1), C_TEXT),
                ("TOPPADDING", (0,0), (-1,-1), 4),
                ("BOTTOMPADDING", (0,0), (-1,-1), 4),
                ("LEFTPADDING", (0,0), (-1,-1), 8),
                ("RIGHTPADDING", (0,0), (-1,-1), 8),
                ("LINEBELOW", (0,0), (-1,-2), 0.3, C_BORDER),
            ]))
            story.append(t)

    # ── Summary ──────────────────────────────────────────────────────────────
    story += _section_divider("Diagnosis Summary", styles)
    if loss_val == 0:
        summary = "Host is reachable with no packet loss. Network path appears healthy."
        s_style = styles["ok"]
    elif loss_val < 50:
        summary = f"Host reachable but experiencing {loss} packet loss. Possible network congestion or instability."
        s_style = styles["warn"]
    else:
        summary = f"High packet loss ({loss}) detected. Host may be unreachable or heavily filtered."
        s_style = styles["err"]
    story.append(Paragraph(summary, s_style))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "This report was generated by NetScout for authorized diagnostic use only. "
        "Do not use on systems without explicit permission.",
        styles["mono_muted"]))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()


def generate_vpn_report(target: str, ip: str, check_results: list[dict],
                         overall: str, notes: str = "") -> bytes:
    """
    Generate PDF report for VPN/PAM/Jumphost connectivity checks.
    check_results: list of dicts with keys: service, port, protocol, status, latency, detail
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN, bottomMargin=20*mm,
    )
    styles = _styles()
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    story = []

    story.append(_header_table(target, ip, ts, "VPN / PAM / Jumphost Check", styles))
    story.append(HRFlowable(width="100%", thickness=1, color=C_BLUE, spaceAfter=8))

    # ── Target ───────────────────────────────────────────────────────────────
    story += _section_divider("Target Information", styles)
    ov_status = "ok" if overall == "REACHABLE" else ("warn" if overall == "PARTIAL" else "err")
    story.append(_kv_table([
        ("Target Host",      target,  "value"),
        ("Resolved IP",      ip,      "value"),
        ("Timestamp",        ts,      "value"),
        ("Overall Status",   overall, ov_status),
    ], styles))

    # ── Check Results ────────────────────────────────────────────────────────
    story += _section_divider("Port & Service Connectivity Results", styles)

    tdata = [["Service", "Port", "Proto", "Status", "Latency", "Detail"]]
    col_w = [32*mm, 16*mm, 16*mm, 20*mm, 20*mm, PAGE_W-2*MARGIN-104*mm]

    for r in check_results:
        status = r.get("status", "unknown").upper()
        tdata.append([
            r.get("service", ""),
            str(r.get("port", "")),
            r.get("protocol", "TCP"),
            status,
            r.get("latency", "—"),
            r.get("detail", ""),
        ])

    t = Table(tdata, colWidths=col_w)
    row_colors = []
    for i, row in enumerate(tdata[1:], 1):
        st = row[3]
        if "OPEN" in st:
            row_colors.append(("BACKGROUND", (3,i), (3,i), colors.HexColor("#0d2e15")))
            row_colors.append(("TEXTCOLOR", (3,i), (3,i), C_GREEN))
        elif "CLOSED" in st or "ERROR" in st:
            row_colors.append(("BACKGROUND", (3,i), (3,i), colors.HexColor("#2e0d0d")))
            row_colors.append(("TEXTCOLOR", (3,i), (3,i), C_RED))
        else:
            row_colors.append(("BACKGROUND", (3,i), (3,i), colors.HexColor("#2e200d")))
            row_colors.append(("TEXTCOLOR", (3,i), (3,i), C_YELLOW))

    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), C_BORDER),
        ("TEXTCOLOR", (0,0), (-1,0), C_BLUE),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,-1), 8),
        ("FONTNAME", (0,1), (-1,-1), "Courier"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [C_PANEL, colors.HexColor("#1a1f27")]),
        ("TEXTCOLOR", (0,1), (-1,-1), C_TEXT),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("LINEBELOW", (0,0), (-1,-2), 0.3, C_BORDER),
    ] + row_colors))
    story.append(t)

    # ── Summary ───────────────────────────────────────────────────────────────
    story += _section_divider("Diagnosis & Recommendation", styles)

    open_ports  = [r for r in check_results if "open"  in r.get("status","").lower()]
    closed_ports= [r for r in check_results if "closed" in r.get("status","").lower() or
                                                "error"  in r.get("status","").lower()]

    if open_ports:
        story.append(Paragraph(
            f"REACHABLE services ({len(open_ports)}): " +
            ", ".join(f"{r['service']} :{r['port']}" for r in open_ports),
            styles["ok"]))
    if closed_ports:
        story.append(Paragraph(
            f"UNREACHABLE services ({len(closed_ports)}): " +
            ", ".join(f"{r['service']} :{r['port']}" for r in closed_ports),
            styles["err"]))

    story.append(Spacer(1, 6))

    if overall == "REACHABLE":
        story.append(Paragraph(
            "All checked endpoints are reachable. If users still cannot connect, "
            "the issue is likely at the authentication layer (credentials, MFA, certificates) "
            "rather than network connectivity.",
            styles["value"]))
    elif overall == "PARTIAL":
        story.append(Paragraph(
            "Some endpoints are reachable while others are blocked. "
            "Check firewall rules, security groups, or routing policies for the blocked services. "
            "Tenant connectivity issues are likely related to the unreachable services above.",
            styles["warn"]))
    else:
        story.append(Paragraph(
            "No endpoints are reachable. Likely causes: firewall blocking all traffic, "
            "incorrect IP/hostname, host is down, or routing issue between source and target.",
            styles["err"]))

    if notes:
        story.append(Spacer(1, 6))
        story.append(Paragraph("Additional Notes:", styles["label"]))
        story.append(Paragraph(notes, styles["mono"]))

    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "This report was generated by NetScout for authorized diagnostic use only. "
        "Do not use on systems without explicit permission.",
        styles["mono_muted"]))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
