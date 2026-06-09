import os
import sys
from datetime import datetime
from pathlib import Path

# Add project root to python path to access backend logic
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from backend.app.reports.pdf_gen import generate_pdf_report
from backend.app.reports.md_gen import generate_markdown_report

def test_report_compilation_and_existence(tmp_path):
    pdf_out = str(tmp_path / "test_report.pdf")
    md_out = str(tmp_path / "test_report.md")
    
    review_title = "Firewall ACL Overhaul"
    status = "reviewed"
    risk_score = 75
    risk_level = "high"
    created_at = datetime.utcnow()
    creator_email = "engineer@enterprise.internal"
    
    stats = {
        "added": 12,
        "removed": 5,
        "modified": 3,
        "unchanged": 150,
        "total_old": 158,
        "total_new": 165
    }
    
    rules_triggered = [
        {
            "rule_id": "acl_widening",
            "rule_name": "Access Control List Widening",
            "severity": "critical",
            "description": "Permit ip any any detected.",
            "matched_lines": ["Line 42: permit ip any any"]
        },
        {
            "rule_id": "telnet_enabled",
            "rule_name": "Unencrypted Telnet Management Allowed",
            "severity": "high",
            "description": "transport input telnet configured.",
            "matched_lines": ["Line 89: transport input telnet"]
        }
    ]
    
    ip_findings = [
        {
            "ip": "198.51.100.42",
            "reputation_score": 85,
            "is_malicious": True,
            "details": "Known malicious source address."
        }
    ]
    
    executive_summary = "AI Summary: Configuration changes widen ACL access lists and enable insecure management via Telnet."
    approval_recommendation = "Status: Reject. The widening of security controls violates policy."
    ai_risk_analysis = "High severity issues detected. Standard compliance rules failed."
    reviewer_notes = "Rollback plan: apply previous baseline immediately."

    # Generate PDF
    pdf_result = generate_pdf_report(
        output_path=pdf_out,
        review_title=review_title,
        status=status,
        risk_score=risk_score,
        risk_level=risk_level,
        created_at=created_at,
        creator_email=creator_email,
        stats=stats,
        rules_triggered=rules_triggered,
        ip_findings=ip_findings,
        executive_summary=executive_summary,
        approval_recommendation=approval_recommendation,
        ai_risk_analysis=ai_risk_analysis,
        reviewer_notes=reviewer_notes
    )
    
    # Generate Markdown
    md_result = generate_markdown_report(
        output_path=md_out,
        review_title=review_title,
        status=status,
        risk_score=risk_score,
        risk_level=risk_level,
        created_at=created_at,
        creator_email=creator_email,
        stats=stats,
        rules_triggered=rules_triggered,
        ip_findings=ip_findings,
        executive_summary=executive_summary,
        approval_recommendation=approval_recommendation,
        ai_risk_analysis=ai_risk_analysis,
        reviewer_notes=reviewer_notes
    )

    # Verify files created and are non-empty
    assert os.path.exists(pdf_result)
    assert os.path.getsize(pdf_result) > 0
    
    assert os.path.exists(md_result)
    assert os.path.getsize(md_result) > 0
    
    with open(md_result, "r", encoding="utf-8") as f:
        md_text = f.read()
        assert "Firewall ACL Overhaul" in md_text
        assert "Composite Risk Score:** 75 / 100" in md_text
        assert "198.51.100.42" in md_text
        assert "acl_widening" not in md_text # Verify we formatted the name properly
        assert "Access Control List Widening" in md_text
