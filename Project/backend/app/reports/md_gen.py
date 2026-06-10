import os
from datetime import datetime

def generate_markdown_report(
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
    Generates a structured Markdown (.md) report of the network configuration review.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Format rules triggered table
    rules_table = ""
    if rules_triggered:
        rules_table = "\n### Triggered Security & Compliance Rules\n\n| Rule Name | Severity | Description |\n| :--- | :--- | :--- |\n"
        for rule in rules_triggered:
            rules_table += f"| {rule.get('rule_name', '')} | **{rule.get('severity', '').upper()}** | {rule.get('description', '')} |\n"
    
    # Format IP findings table
    ip_table = ""
    if ip_findings:
        ip_table = "\n### Public IP Reputation Verification Logs\n\n| IP Address | Abuse Score | Malicious | Reputation details |\n| :--- | :--- | :--- | :--- |\n"
        for ip in ip_findings:
            malicious_flag = "⚠️ YES" if ip.get("is_malicious") else "✅ NO"
            ip_table += f"| {ip.get('ip', '')} | {ip.get('reputation_score', 0)}% | {malicious_flag} | {ip.get('details', '')} |\n"

    md_content = f"""# Network Configuration Review Report

## Meta Information
- **Review Title:** {review_title}
- **Review ID:** {os.path.basename(output_path).split('_')[0]}
- **Date/Timestamp:** {created_at.strftime("%Y-%m-%d %H:%M:%S UTC")}
- **Requested By:** {creator_email}
- **Overall Status:** {status.upper()}
- **Composite Risk Score:** {risk_score} / 100
- **Overall Risk Level:** **{risk_level.upper()}**

---

## 1. Executive Summary
{executive_summary}

---

## 2. Configuration Change Statistics
- **Lines Added:** {stats.get("added", 0)}
- **Lines Removed:** {stats.get("removed", 0)}
- **Lines Modified:** {stats.get("modified", 0)}
- **Lines Unchanged:** {stats.get("unchanged", 0)}
- **Total lines in Old Config:** {stats.get("total_old", 0)}
- **Total lines in New Config:** {stats.get("total_new", 0)}

---

## 3. Security Assessment & Risk Analysis
{ai_risk_analysis}
{rules_table}
{ip_table}

---

## 4. Approval Recommendation
{approval_recommendation}

---

## 5. Reviewer Deployment & Rollback Notes
{reviewer_notes}

---
*Report automatically compiled by Network Config Diff Reviewer Agent Workflow on {datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}*
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(md_content)
        
    return output_path
