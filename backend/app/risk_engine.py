import re
from typing import Dict, Any, List

# Rule Definitions
# Each rule contains a pattern, name, severity, base score contribution, and details.
RULES = [
    {
        "id": "acl_widening",
        "name": "Access Control List Widening",
        "pattern": r"permit\s+(ip|tcp|udp)\s+any\s+any",
        "severity": "critical",
        "score": 40,
        "description": "Network access control list (ACL) was widened to permit traffic from any source to any destination. This severely increases the attack surface."
    },
    {
        "id": "telnet_enabled",
        "name": "Unencrypted Telnet Management Allowed",
        "pattern": r"transport\s+input\s+.*telnet.*",
        "severity": "high",
        "score": 30,
        "description": "Telnet protocols allow administrative credentials to be transmitted in plaintext across the network. Secure Shell (SSH) should be enforced."
    },
    {
        "id": "snmp_common_community",
        "name": "Default/Common SNMP Community String",
        "pattern": r"snmp-server\s+community\s+(public|private)\s+",
        "severity": "high",
        "score": 30,
        "description": "SNMP configuration uses common defaults ('public' or 'private'). This allows attackers to easily query or modify network metrics and configurations."
    },
    {
        "id": "plaintext_password",
        "name": "Plaintext Username Password Configuration",
        "pattern": r"username\s+\S+\s+password\s+(0\s+)?\S+",
        "severity": "high",
        "score": 30,
        "description": "Plaintext or poorly hashed username password configuration detected. Strong hashing algorithms (like 'secret') must be used."
    },
    {
        "id": "enable_plaintext_password",
        "name": "Plaintext Enable Password Configuration",
        "pattern": r"enable\s+password\s+(0\s+)?\S+",
        "severity": "high",
        "score": 30,
        "description": "Plaintext or poorly hashed 'enable password' configuration detected. 'enable secret' with PBKDF2/scrypt/SHA-256 encryption must be used."
    },
    {
        "id": "snmp_changed",
        "name": "SNMP Server Configuration Added/Modified",
        "pattern": r"snmp-server\s+community\s+\S+",
        "severity": "medium",
        "score": 15,
        "description": "An SNMP community string was added or altered. Validate if community strings are cryptographically secure and access is ACL restricted."
    },
    {
        "id": "port_exposure_ssh_telnet_rdp",
        "name": "Remote Management Port Exposed",
        "pattern": r"permit\s+tcp\s+any\s+any\s+eq\s+(22|23|3389|80|443)",
        "severity": "high",
        "score": 25,
        "description": "Management ports (SSH/Telnet/RDP) or HTTP/HTTPS are exposed from any external host. Remote access should be restricted to VPN and jump hosts."
    },
    {
        "id": "default_route_change",
        "name": "Default Route Created/Modified",
        "pattern": r"ip\s+route\s+0\.0\.0\.0\s+0\.0\.0\.0\s+",
        "severity": "high",
        "score": 20,
        "description": "A new gateway or default route was added or modified. This changes the path for all out-of-band traffic leaving the system."
    },
    {
        "id": "route_added",
        "name": "Static Route Added",
        "pattern": r"ip\s+route\s+(?!0\.0\.0\.0\s+0\.0\.0\.0)\d+\.\d+\.\d+\.\d+",
        "severity": "low",
        "score": 10,
        "description": "A static route was added to the configuration, altering packet forwarding paths for specified subnets."
    },
    {
        "id": "route_removed",
        "name": "Static Route Removed",
        "pattern": r"no\s+ip\s+route\s+",
        "severity": "low",
        "score": 10,
        "description": "A static route was removed. Traffic meant for these destinations may failover to default paths or become blackholed."
    },
    {
        "id": "bgp_changed",
        "name": "BGP Protocol Configuration Changed",
        "pattern": r"(router\s+bgp\s+|neighbor\s+\S+\s+)",
        "severity": "medium",
        "score": 15,
        "description": "Border Gateway Protocol (BGP) neighbors or route rules changed. This could affect public routing announcements and external trust."
    },
    {
        "id": "ospf_changed",
        "name": "OSPF Protocol Configuration Changed",
        "pattern": r"(router\s+ospf\s+|network\s+\S+\s+area\s+)",
        "severity": "medium",
        "score": 15,
        "description": "Open Shortest Path First (OSPF) routing domains or networks altered. Ensure route filters are updated to prevent route poisoning."
    },
    {
        "id": "nat_changed",
        "name": "NAT Rule Configuration Added/Modified",
        "pattern": r"ip\s+nat\s+(inside|outside|source)\s+",
        "severity": "medium",
        "score": 15,
        "description": "Network Address Translation (NAT) rules were changed. Verify if these map internal hosts to public interfaces or expose new interfaces."
    },
    {
        "id": "vpn_changed",
        "name": "VPN or Tunnel Interface Configuration Changed",
        "pattern": r"(crypto\s+map|crypto\s+isakmp|crypto\s+ipsec|interface\s+Tunnel)",
        "severity": "medium",
        "score": 15,
        "description": "IPsec VPN encryption profiles or Tunnel interfaces were configured. Verify encryption strength and keying parameters."
    },
    {
        "id": "dns_changed",
        "name": "DNS Name Server Altered",
        "pattern": r"ip\s+name-server\s+",
        "severity": "low",
        "score": 5,
        "description": "Active DNS servers were configured or changed. Ensure these point to trusted internal name servers or secure public resolvers."
    },
    {
        "id": "interface_no_shutdown",
        "name": "Interface Enabled (no shutdown)",
        "pattern": r"no\s+shutdown",
        "severity": "medium",
        "score": 10,
        "description": "A physical or logical port has been enabled ('no shutdown'). Ensure this interface is connected and secured properly."
    },
    {
        "id": "management_access_changed",
        "name": "Line VTY / Console Configuration Changed",
        "pattern": r"line\s+(vty|con)\s+\d+",
        "severity": "low",
        "score": 5,
        "description": "Management terminal line access parameters modified. Ensure timeouts, logging, and access control settings are maintained."
    }
]

def analyze_config_risks(diff_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Scans the JSON diff representation for network configuration security risks.
    Analyzes added/modified lines.
    Returns:
        rules_triggered: List of triggered rules containing descriptions, severity, matched lines.
        risk_score: Integer (0-100)
        risk_level: str ("low", "medium", "high", "critical")
    """
    triggered = {}
    lines = diff_json.get("lines", [])

    for line in lines:
        # Check added and modified lines for vulnerability indicators
        # Also check removed lines for specific "no ip route" or route removals
        ltype = line.get("type")
        content = line.get("content", "")
        
        # Normalize content for pattern matching
        normalized_content = content.strip().lower()

        # For modified lines, check both the old and new contents
        contents_to_check = [normalized_content]
        if ltype == "modified" and "new_content" in line:
            contents_to_check = [line["new_content"].strip().lower()]
        elif ltype == "removed":
            # Some actions (like route removals) are triggered on removal
            contents_to_check = [f"no {normalized_content}"]

        for rule in RULES:
            # Skip if we already matched this rule and recorded it, unless we want to collect all matched lines
            for code in contents_to_check:
                if re.search(rule["pattern"], code, re.IGNORECASE):
                    rule_id = rule["id"]
                    if rule_id not in triggered:
                        triggered[rule_id] = {
                            "rule_id": rule_id,
                            "rule_name": rule["name"],
                            "severity": rule["severity"],
                            "description": rule["description"],
                            "score": rule["score"],
                            "matched_lines": []
                        }
                    # Keep track of the original line content for context
                    full_line_info = f"Line {line.get('new_lineno') or line.get('old_lineno') or '?'}: {content}"
                    if full_line_info not in triggered[rule_id]["matched_lines"]:
                        triggered[rule_id]["matched_lines"].append(full_line_info)

    # Calculate final composite score
    total_score = 0
    triggered_list = []
    
    for rule_id, data in triggered.items():
        total_score += data["score"]
        # Limit matched lines to avoid giant reports
        data["matched_lines"] = data["matched_lines"][:5]
        triggered_list.append(data)

    # Cap composite score at 100
    risk_score = min(total_score, 100)

    # Map score to risk levels
    if risk_score <= 20:
        risk_level = "low"
    elif risk_score <= 50:
        risk_level = "medium"
    elif risk_score <= 80:
        risk_level = "high"
    else:
        risk_level = "critical"

    return {
        "rules_triggered": triggered_list,
        "risk_score": risk_score,
        "risk_level": risk_level
    }
