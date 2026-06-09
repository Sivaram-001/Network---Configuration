import sys
from pathlib import Path

# Add project root to python path to access backend logic
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from backend.app.external.reputation import extract_ips, check_ip_reputation

def test_extract_ips_filters_private():
    config_text = """
    ip route 10.1.1.0 255.255.255.0 10.1.1.254
    ip route 192.168.5.0 255.255.255.0 192.168.5.1
    ip address 172.16.20.1 255.255.255.0
    ! Public IPs in ACLs or DNS config
    ip name-server 8.8.8.8
    ip name-server 1.1.1.1
    ip route 0.0.0.0 0.0.0.0 198.51.100.42
    ! Wildcards & loopbacks
    ip route 127.0.0.1 255.255.255.255
    """
    
    extracted = extract_ips(config_text)
    
    # Assert public IPs are extracted
    assert "8.8.8.8" in extracted
    assert "1.1.1.1" in extracted
    assert "198.51.100.42" in extracted
    
    # Assert private/loopback/wildcard IPs are filtered out
    assert "10.1.1.254" not in extracted
    assert "192.168.5.1" not in extracted
    assert "172.16.20.1" not in extracted
    assert "127.0.0.1" not in extracted
    assert "0.0.0.0" not in extracted

def test_ip_reputation_safe():
    # Test safe public IP
    res = check_ip_reputation("8.8.8.8")
    assert res["ip"] == "8.8.8.8"
    assert res["reputation_score"] == 0
    assert res["is_malicious"] is False
    assert "Google" in res["details"]

def test_ip_reputation_malicious():
    # Test known malicious IP in mock registry
    res = check_ip_reputation("198.51.100.42")
    assert res["ip"] == "198.51.100.42"
    assert res["reputation_score"] == 85
    assert res["is_malicious"] is True
    assert "AbuseIPDB" in res["details"]
    assert "VirusTotal" in res["details"]
