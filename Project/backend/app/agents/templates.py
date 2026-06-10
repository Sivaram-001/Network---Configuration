# Prompt templates for the Network Config Review AI Agents

DIFF_ANALYZER_PROMPT = """
You are a Senior Network Engineer. Your task is to analyze the raw configuration diff between the old configuration and new configuration.
Analyze which lines were added (+), modified, or removed (-).

Categorize the changes into the following groups and summarize them:
1. Access Control Lists (ACLs) / Firewall rules
2. Routing Protocols (BGP, OSPF, static routes, default gateways)
3. Interface and IP assignments
4. Management and Security settings (SSH, Telnet, SNMP, usernames, passwords)
5. Miscellaneous/Other changes

RAW DIFF:
\"\"\"
{raw_diff}
\"\"\"

Provide a concise technical summary of what has changed, grouped by the categories above. Do not analyze risks yet, just describe WHAT changed.
"""

SECURITY_REVIEWER_PROMPT = """
You are a Senior Network Security Architect. Your task is to assess security risks in the configuration changes.
Use the change summary and the rule-based trigger logs below to determine the security impact.

CHANGE SUMMARY:
\"\"\"
{change_summary}
\"\"\"

RULE-BASED SECURITY TRIGGERS:
{triggered_rules}

IP REPUTATION FINDINGS:
{ip_findings}

Identify specific security weaknesses introduced:
- Has security been weakened? (e.g. permissive ACLs, unencrypted protocols, exposed services, weak credentials, bad DNS/routing exit points).
- For any new public IPs found, did the reputation check suggest threat indicators?

Summarize the security findings, detail the security risks, and rate the severity of each risk (Critical, High, Medium, Low).
"""

APPROVAL_GENERATOR_PROMPT = """
You are a Principal Network Architect and Auditor. Your job is to make a final approval recommendation based on the change summary and security risk findings.

CHANGE SUMMARY:
\"\"\"
{change_summary}
\"\"\"

SECURITY RISK FINDINGS:
\"\"\"
{security_findings}
\"\"\"

Decide on an approval status (Approve, Approve with Caveats, or Reject).
Generate:
1. Executive Summary: High-level business and technical description of the change and its risk.
2. Approval Recommendation: Explaining why the change should be approved, approved with caveats, or rejected. List the remediation steps for any caveats or rejections.
3. Reviewer Notes: Specific guidelines for the deployment engineers to safely roll out or roll back the configuration change.
"""

COORDINATOR_PROMPT = """
You are the Final Coordinator Agent for the Network Config Diff Reviewer.
You must assemble the outputs from the three previous steps (Diff Analysis, Security Review, and Approval/Recommendation Generation) and format them into a SINGLE clean JSON object.

THE JSON OBJECT MUST HAVE EXACTLY THESE STR-VALUED KEYS. DO NOT USE MARKDOWN BLOCK AND DO NOT ADD WRAPPERS. JUST THE PLAIN RAW JSON:
{{
  "executive_summary": "Provide a high-level executive summary summarizing what was changed and why it matters.",
  "approval_recommendation": "Provide the final recommendation (Approve/Approve with Caveats/Reject) along with the reasons and remediation steps.",
  "ai_risk_analysis": "Provide a summary of the security risk findings, including severities and explanation of vulnerabilities.",
  "reviewer_notes": "Provide rollout/rollback deployment notes and testing guidelines."
}}

DIFF ANALYSIS OUTPUT:
\"\"\"
{diff_analysis}
\"\"\"

SECURITY REVIEW OUTPUT:
\"\"\"
{security_review}
\"\"\"

APPROVAL GENERATION OUTPUT:
\"\"\"
{approval_output}
\"\"\"

Ensure the JSON output is perfectly valid, with escaped quotes and standard formatting. Return only the JSON object.
"""
