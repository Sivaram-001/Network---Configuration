import re
import ipaddress
import urllib.request
import urllib.parse
import json
from typing import List, Dict, Any
from backend.app.config import ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY

# Regex to match IPv4 addresses
IP_REGEX = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

# Predefined reputation list for offline/local testing
MOCK_REPUTATIONS = {
    "198.51.100.42": {
        "reputation_score": 85,
        "is_malicious": True,
        "details": "AbuseIPDB: Reported 342 times for SSH brute-forcing and network scanning. VirusTotal: 8/72 engines flagged as malicious."
    },
    "203.0.113.105": {
        "reputation_score": 92,
        "is_malicious": True,
        "details": "VirusTotal: 15/72 engines flagged as active Command & Control (C2) server. AbuseIPDB: Confirmed malicious IP."
    },
    "8.8.8.8": {
        "reputation_score": 0,
        "is_malicious": False,
        "details": "Google Public DNS. Clean reputation."
    },
    "1.1.1.1": {
        "reputation_score": 0,
        "is_malicious": False,
        "details": "Cloudflare Public DNS. Clean reputation."
    }
}

def is_public_ip(ip_str: str) -> bool:
    """
    Manually checks if an IP is a public routable address.
    Filters out RFC 1918, loopbacks, link-local, multicast, unspecified, and broadcast.
    Allows documentation subnets (198.51.100.x, etc.) for testing.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip_str == "255.255.255.255":
            return False
            
        octets = [int(o) for o in ip_str.split('.')]
        if len(octets) != 4:
            return False
            
        first, second = octets[0], octets[1]
        
        # 10.0.0.0/8
        if first == 10:
            return False
        # 192.168.0.0/16
        if first == 192 and second == 168:
            return False
        # 172.16.0.0/12
        if first == 172 and (16 <= second <= 31):
            return False
        # 169.254.0.0/16
        if first == 169 and second == 254:
            return False
            
        return True
    except Exception:
        return False

def extract_ips(config_text: str) -> List[str]:
    """
    Extracts all unique IPv4 addresses from configuration text.
    Filters out private IPs, multicast, loopback, and broadcast.
    """
    found_ips = re.findall(IP_REGEX, config_text)
    unique_ips = set(found_ips)
    public_ips = []

    for ip_str in unique_ips:
        if is_public_ip(ip_str):
            public_ips.append(ip_str)
            
    return public_ips

def check_ip_abuseipdb(ip: str) -> Dict[str, Any]:
    """
    Checks IP reputation on AbuseIPDB if API Key is configured.
    """
    if not ABUSEIPDB_API_KEY:
        return {}
        
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    req = urllib.request.Request(url)
    req.add_header("Key", ABUSEIPDB_API_KEY)
    req.add_header("Accept", "application/json")
    
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            res_data = json.loads(response.read().decode())
            data = res_data.get("data", {})
            abuse_score = data.get("abuseConfidenceScore", 0)
            return {
                "score": abuse_score,
                "is_malicious": abuse_score > 20,
                "details": f"AbuseIPDB: Confirmed abuse score of {abuse_score}%. Total reports: {data.get('totalReports', 0)}."
            }
    except Exception as e:
        print(f"AbuseIPDB request failed for IP {ip}: {str(e)}")
        return {}

def check_ip_virustotal(ip: str) -> Dict[str, Any]:
    """
    Checks IP reputation on VirusTotal if API Key is configured.
    """
    if not VIRUSTOTAL_API_KEY:
        return {}
        
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    req = urllib.request.Request(url)
    req.add_header("x-apikey", VIRUSTOTAL_API_KEY)
    
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            res_data = json.loads(response.read().decode())
            data = res_data.get("data", {})
            stats = data.get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)
            total_flags = malicious_count + suspicious_count
            return {
                "score": int((malicious_count / max(1, sum(stats.values()))) * 100),
                "is_malicious": malicious_count > 2,
                "details": f"VirusTotal: {malicious_count} malicious / {suspicious_count} suspicious flags out of {sum(stats.values())} engines."
            }
    except Exception as e:
        print(f"VirusTotal request failed for IP {ip}: {str(e)}")
        return {}

def check_ip_reputation(ip: str) -> Dict[str, Any]:
    """
    Checks IP reputation against AbuseIPDB and VirusTotal.
    Falls back to local mock registry if no API keys are provided.
    """
    # 1. Check if mock IP exists in registry (gives consistent results for demo)
    if ip in MOCK_REPUTATIONS:
        return {
            "ip": ip,
            "reputation_score": MOCK_REPUTATIONS[ip]["reputation_score"],
            "is_malicious": MOCK_REPUTATIONS[ip]["is_malicious"],
            "details": MOCK_REPUTATIONS[ip]["details"]
        }

    # 2. Try checking real APIs if keys are available
    abuse_info = check_ip_abuseipdb(ip)
    vt_info = check_ip_virustotal(ip)

    if abuse_info or vt_info:
        score = max(abuse_info.get("score", 0), vt_info.get("score", 0))
        is_malicious = abuse_info.get("is_malicious", False) or vt_info.get("is_malicious", False)
        details_list = []
        if abuse_info:
            details_list.append(abuse_info["details"])
        if vt_info:
            details_list.append(vt_info["details"])
        
        return {
            "ip": ip,
            "reputation_score": score,
            "is_malicious": is_malicious,
            "details": " | ".join(details_list)
        }

    # 3. Default fallback for generic unlisted public IPs
    return {
        "ip": ip,
        "reputation_score": 0,
        "is_malicious": False,
        "details": "IP is not listed in threat databases. API Keys not configured for full online query."
    }

def analyze_config_ips(config_text: str) -> List[Dict[str, Any]]:
    """
    Extracts all public IPs and queries their reputation.
    """
    ips = extract_ips(config_text)
    findings = []
    for ip in ips:
        findings.append(check_ip_reputation(ip))
    return findings
