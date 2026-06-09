import sys
from pathlib import Path

# Add project root to python path to access backend logic
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from backend.app.agents.workflow import run_agent_workflow, get_deterministic_fallback

def test_deterministic_fallback_no_vulns():
    raw_diff = "unchanged line 1\nunchanged line 2"
    triggered_rules = []
    ip_findings = []
    
    res = get_deterministic_fallback(raw_diff, triggered_rules, ip_findings)
    
    assert "executive_summary" in res
    assert "approval_recommendation" in res
    assert "ai_risk_analysis" in res
    assert "reviewer_notes" in res
    
    assert "No security or compliance" in res["executive_summary"]
    assert "APPROVED: The configuration" in res["approval_recommendation"]

def test_deterministic_fallback_critical_vulns():
    raw_diff = "+ permit ip any any"
    triggered_rules = [
        {
            "rule_id": "acl_widening",
            "rule_name": "Access Control List Widening",
            "severity": "critical",
            "description": "Permit ip any any detected.",
            "matched_lines": ["Line 2: permit ip any any"]
        }
    ]
    ip_findings = [
        {
            "ip": "203.0.113.105",
            "reputation_score": 92,
            "is_malicious": True,
            "details": "Known malicious source address."
        }
    ]
    
    res = get_deterministic_fallback(raw_diff, triggered_rules, ip_findings)
    
    # Assert rejection
    assert "Reject" in res["approval_recommendation"]
    assert "Remove permissive Access List" in res["approval_recommendation"]
    assert "203.0.113.105" in res["approval_recommendation"]
    
    # Assert risk analysis logs
    assert "[CRITICAL] Access Control List Widening" in res["ai_risk_analysis"]
    assert "Line 2: permit ip any any" in res["ai_risk_analysis"]

def test_run_agent_workflow_offline():
    # If API keys are not loaded, run_agent_workflow should catch the exception
    # and execute the fallback gracefully.
    raw_diff = "+ permit ip any any"
    triggered_rules = [
        {
            "rule_id": "acl_widening",
            "rule_name": "Access Control List Widening",
            "severity": "critical",
            "description": "Permit ip any any detected.",
            "matched_lines": ["Line 2: permit ip any any"]
        }
    ]
    ip_findings = []
    
    res = run_agent_workflow(raw_diff, triggered_rules, ip_findings)
    
    # Assert it completed and returned correct structure
    assert "executive_summary" in res
    assert "approval_recommendation" in res
    assert "ai_risk_analysis" in res
    assert "reviewer_notes" in res
