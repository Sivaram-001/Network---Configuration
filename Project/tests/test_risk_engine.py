import sys
from pathlib import Path

# Add project root to python path to access backend logic
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from backend.app.risk_engine import analyze_config_risks

def test_risk_engine_low_risk():
    diff_json = {
        "lines": [
            {"type": "unchanged", "content": "interface GigabitEthernet0/1"},
            {"type": "added", "content": " description Web Server Interface"}
        ]
    }
    res = analyze_config_risks(diff_json)
    
    assert res["risk_score"] == 0
    assert res["risk_level"] == "low"
    assert len(res["rules_triggered"]) == 0

def test_risk_engine_critical_acl_widening():
    diff_json = {
        "lines": [
            {"type": "added", "content": "ip access-list extended outer-boundary"},
            {"type": "added", "content": " permit ip any any"} # Triggers acl_widening (40 pts)
        ]
    }
    res = analyze_config_risks(diff_json)
    
    # 40 points is categorized as Medium risk (21-50 range)
    # Wait, rules: acl_widening is 40 points. Let's assert:
    assert res["risk_score"] == 40
    assert res["risk_level"] == "medium"
    assert len(res["rules_triggered"]) == 1
    assert res["rules_triggered"][0]["rule_id"] == "acl_widening"

def test_risk_engine_multiple_vulns():
    diff_json = {
        "lines": [
            {"type": "added", "content": " permit ip any any"}, # acl_widening: 40 pts
            {"type": "added", "content": "transport input telnet"}, # telnet_enabled: 30 pts
            {"type": "added", "content": "snmp-server community public RO"}, # snmp_common_community: 30 pts
            {"type": "added", "content": "username admin password admin123"} # plaintext_password: 30 pts
        ]
    }
    res = analyze_config_risks(diff_json)
    
    # Total sum is 40 + 30 + 30 + 30 = 130, which should be capped at 100
    assert res["risk_score"] == 100
    assert res["risk_level"] == "critical"
    
    triggered_rules = [r["rule_id"] for r in res["rules_triggered"]]
    assert "acl_widening" in triggered_rules
    assert "telnet_enabled" in triggered_rules
    assert "snmp_common_community" in triggered_rules
    assert "plaintext_password" in triggered_rules
