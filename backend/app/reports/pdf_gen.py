import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_pdf_report(
    output_path: str,
    review_title: str,
    status: str,
    risk_score: int,
    risk_level: str,
    created_at: datetime,
    creator_email: str,
    stats: dict,
    rules_triggered: list,
    ip_findings: list,
    executive_summary: str,
    approval_recommendation: str,
    ai_risk_analysis: str,
    reviewer_notes: str
) -> str:
    """
    Generates a professional PDF report for the config review using ReportLab.
    """
    # Create directory if it doesn't exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom Styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0F172A'), # Deep navy
        spaceAfter=15
    )
    
    section_style = ParagraphStyle(
        'SectionHeader',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=colors.HexColor('#1E293B'),
        spaceBefore=15,
        spaceAfter=8,
        keepWithNext=True
    )
    
    body_style = ParagraphStyle(
        'ReportBody',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#334155'),
        spaceAfter=8
    )
    
    meta_label_style = ParagraphStyle(
        'MetaLabel',
        parent=body_style,
        fontName='Helvetica-Bold',
        textColor=colors.HexColor('#1E293B')
    )
    
    bullet_style = ParagraphStyle(
        'BulletText',
        parent=body_style,
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=4
    )

    # Color coding for risk level
    level_colors = {
        "low": colors.HexColor('#22C55E'), # Green
        "medium": colors.HexColor('#EAB308'), # Yellow
        "high": colors.HexColor('#F97316'), # Orange
        "critical": colors.HexColor('#EF4444') # Red
    }
    level_color = level_colors.get(risk_level.lower(), colors.HexColor('#64748B'))

    story = []

    # Title
    story.append(Paragraph("Network Configuration Review Report", title_style))
    story.append(Paragraph(f"Review Title: {review_title}", styles['Heading3']))
    story.append(Spacer(1, 10))

    # Metadata Table
    meta_data = [
        [Paragraph("Review ID:", meta_label_style), Paragraph(os.path.basename(output_path).split('_')[0], body_style),
         Paragraph("Created At:", meta_label_style), Paragraph(created_at.strftime("%Y-%m-%d %H:%M:%S"), body_style)],
        [Paragraph("Requested By:", meta_label_style), Paragraph(creator_email, body_style),
         Paragraph("Status:", meta_label_style), Paragraph(status.upper(), body_style)],
        [Paragraph("Risk Score:", meta_label_style), Paragraph(f"<b>{risk_score} / 100</b>", body_style),
         Paragraph("Risk Level:", meta_label_style), Paragraph(f"<font color='{level_color}'><b>{risk_level.upper()}</b></font>", body_style)]
    ]
    
    meta_table = Table(meta_data, colWidths=[90, 180, 90, 180])
    meta_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('LINEBELOW', (0, -1), (-1, -1), 1, colors.HexColor('#E2E8F0')),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 15))

    # 1. Executive Summary
    story.append(Paragraph("1. Executive Summary", section_style))
    story.append(Paragraph(executive_summary.replace('\n', '<br/>'), body_style))
    story.append(Spacer(1, 10))

    # 2. Configuration Changes Statistics
    story.append(Paragraph("2. Configuration Change Statistics", section_style))
    stat_data = [
        [Paragraph("Metric", meta_label_style), Paragraph("Count", meta_label_style)],
        [Paragraph("Lines Added", body_style), Paragraph(str(stats.get("added", 0)), body_style)],
        [Paragraph("Lines Removed", body_style), Paragraph(str(stats.get("removed", 0)), body_style)],
        [Paragraph("Lines Modified", body_style), Paragraph(str(stats.get("modified", 0)), body_style)],
        [Paragraph("Lines Unchanged", body_style), Paragraph(str(stats.get("unchanged", 0)), body_style)],
        [Paragraph("Total Old Config Lines", body_style), Paragraph(str(stats.get("total_old", 0)), body_style)],
        [Paragraph("Total New Config Lines", body_style), Paragraph(str(stats.get("total_new", 0)), body_style)]
    ]
    
    stat_table = Table(stat_data, colWidths=[200, 100])
    stat_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F8FAFC')),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(stat_table)
    story.append(Spacer(1, 15))

    # 3. Security Findings
    story.append(Paragraph("3. Security Assessment & Risk Analysis", section_style))
    story.append(Paragraph(ai_risk_analysis.replace('\n', '<br/>'), body_style))
    story.append(Spacer(1, 10))

    # Triggered Rules
    if rules_triggered:
        story.append(Paragraph("Triggered Security & Compliance Rules:", meta_label_style))
        rule_data = [[Paragraph("Rule Name", meta_label_style), Paragraph("Severity", meta_label_style), Paragraph("Description", meta_label_style)]]
        
        for rule in rules_triggered:
            rsev = rule.get("severity", "low").lower()
            rcol = level_colors.get(rsev, colors.HexColor('#64748B'))
            rule_data.append([
                Paragraph(rule.get("rule_name", ""), body_style),
                Paragraph(f"<font color='{rcol}'><b>{rsev.upper()}</b></font>", body_style),
                Paragraph(rule.get("description", ""), body_style)
            ])
            
        rule_table = Table(rule_data, colWidths=[150, 70, 320])
        rule_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F8FAFC')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(rule_table)
        story.append(Spacer(1, 15))
        
    # IP Reputation
    if ip_findings:
        story.append(Paragraph("IP Reputation Verification Logs:", meta_label_style))
        ip_data = [[Paragraph("IP Address", meta_label_style), Paragraph("Rep Score", meta_label_style), Paragraph("Malicious?", meta_label_style), Paragraph("Details / Context", meta_label_style)]]
        
        for finding in ip_findings:
            ismal = "YES" if finding.get("is_malicious") else "NO"
            ipcol = colors.HexColor('#EF4444') if finding.get("is_malicious") else colors.HexColor('#22C55E')
            ip_data.append([
                Paragraph(finding.get("ip", ""), body_style),
                Paragraph(f"{finding.get('reputation_score', 0)}%", body_style),
                Paragraph(f"<font color='{ipcol}'><b>{ismal}</b></font>", body_style),
                Paragraph(finding.get("details", ""), body_style)
            ])
            
        ip_table = Table(ip_data, colWidths=[100, 70, 70, 300])
        ip_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#F8FAFC')),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(ip_table)
        story.append(Spacer(1, 15))

    # Page Break for Recommendation & Notes
    story.append(PageBreak())

    # 4. Approval Recommendation
    story.append(Paragraph("4. Approval Recommendation", section_style))
    story.append(Paragraph(approval_recommendation.replace('\n', '<br/>'), body_style))
    story.append(Spacer(1, 15))

    # 5. Reviewer Deployment Notes
    story.append(Paragraph("5. Reviewer Deployment & Rollback Guidelines", section_style))
    story.append(Paragraph(reviewer_notes.replace('\n', '<br/>'), body_style))
    story.append(Spacer(1, 25))

    # Sign-off Area
    story.append(Paragraph("<b>Approval Verification Signature:</b>", body_style))
    story.append(Spacer(1, 15))
    
    sig_data = [
        [Paragraph("Reviewed By: ___________________________", body_style), Paragraph("Date: ________________________", body_style)],
        [Paragraph("Authorized Signature: __________________", body_style), Paragraph("Decision: [  ] Approved  [  ] Rejected", body_style)]
    ]
    sig_table = Table(sig_data, colWidths=[270, 270])
    sig_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(sig_table)

    doc.build(story)
    return output_path
