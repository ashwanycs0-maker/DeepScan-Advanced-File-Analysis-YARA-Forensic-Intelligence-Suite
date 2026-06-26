from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
import datetime

def generate_pdf(data):
    doc = SimpleDocTemplate("output/report.pdf", pagesize=A4)
    styles = getSampleStyleSheet()
    
    # Custom Styles
    title_style = ParagraphStyle(
        'MainTitle',
        parent=styles['Title'],
        fontSize=22,
        spaceAfter=20,
        textColor=colors.HexColor("#3498db")
    )
    header_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontSize=14,
        spaceBefore=15,
        spaceAfter=10,
        textColor=colors.HexColor("#1c2635")
    )

    elements = []
    
    # Header Info
    elements.append(Paragraph("DeepScan: Forensic Intelligence Suite", title_style))
    elements.append(Paragraph("Automated File Analysis & YARA Forensic Console", styles["Normal"]))
    elements.append(Paragraph(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]))
    elements.append(Spacer(1, 20))

    # 1. RISK ASSESSMENT SUMMARY
    elements.append(Paragraph("1. Threat Risk Assessment", header_style))
    risk_color = colors.red if data['status'] == "HIGH" else colors.orange if data['status'] == "MEDIUM" else colors.green
    risk_table_data = [
        ["METRIC", "VALUE"],
        ["Security Status", data['status']],
        ["Overall Risk Score", f"{data['risk']}%"],
        ["Entropy Level", f"{data['entropy']:.2f}"]
    ]
    t_risk = Table(risk_table_data, colWidths=[150, 300])
    t_risk.setStyle(TableStyle([
        ('BACKGROUND', (1, 1), (1, 1), risk_color),
        ('TEXTCOLOR', (1, 1), (1, 1), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ('PADDING', (0, 0), (-1, -1), 8)
    ]))
    elements.append(t_risk)

    # 2. FILE METADATA
    elements.append(Paragraph("2. File Metadata Information", header_style))
    meta_data = [
        ["Property", "Details"],
        ["Filename", data['file']],
        ["File Size", f"{data['size']} bytes"],
        ["Mime Type", data['type']],
        ["Magic Identifier", data['real_type']],
        ["MD5 Hash", data['md5']],
        ["SHA256 Hash", data['sha256']]
    ]
    t_meta = Table(meta_data, colWidths=[150, 350])
    t_meta.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BACKGROUND', (0, 0), (-1, 0), colors.whitesmoke),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('WORDWRAP', (1, 5), (1, 6), True),
        ('PADDING', (0, 0), (-1, -1), 6)
    ]))
    elements.append(t_meta)

    # 3. SIGNATURE DETECTION (YARA)
    elements.append(Paragraph("3. Signature Match Results (YARA)", header_style))
    yara_matches = data['matches'] if data['matches'] else ["No signatures matched"]
    for match in yara_matches:
        elements.append(Paragraph(f"• {match}", styles["Normal"]))

    # 4. HEURISTIC FEATURES
    elements.append(Paragraph("4. Behavioral Heuristics", header_style))
    features = data['features'] if data['features'] else ["No suspicious heuristics detected"]
    for feature in features:
        elements.append(Paragraph(f"• {feature}", styles["Normal"]))

    # 5. DETAILED LOGS
    elements.append(Paragraph("5. Integrated Analysis Logs", header_style))
    elements.append(Paragraph(data['log'].replace('\n', '<br/>'), styles["Code"]))

    # Footer
    elements.append(Spacer(1, 40))
    elements.append(Paragraph("End of SECURENET Automated Analysis Report", styles["Italic"]))

    doc.build(elements)
