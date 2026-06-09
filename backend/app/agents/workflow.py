import json
import urllib.request
import urllib.parse
from typing import Dict, Any, List
from backend.app.config import (
    OPENAI_API_KEY,
    OPENAI_API_BASE,
    OLLAMA_BASE_URL,
    DEFAULT_MODEL
)
from backend.app.agents.templates import (
    DIFF_ANALYZER_PROMPT,
    SECURITY_REVIEWER_PROMPT,
    APPROVAL_GENERATOR_PROMPT,
    COORDINATOR_PROMPT
)

def call_openai(prompt: str) -> str:
    """
    Calls the OpenAI API.
    """
    url = f"{OPENAI_API_BASE}/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {OPENAI_API_KEY}"
    }
    data = {
        "model": DEFAULT_MODEL,
        "messages": [
            {"role": "system", "content": "You are an expert Network Engineering and Security assistant."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2
    }
    
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers,
        method="POST"
    )
    
    with urllib.request.urlopen(req, timeout=15) as response:
        res = json.loads(response.read().decode("utf-8"))
        return res["choices"][0]["message"]["content"]

def call_ollama(prompt: str) -> str:
    """
    Calls local Ollama instance.
    """
    url = f"{OLLAMA_BASE_URL}/api/generate"
    headers = {
        "Content-Type": "application/json"
    }
    data = {
        "model": DEFAULT_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2
        }
    }
    
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers=headers,
        method="POST"
    )
    
    with urllib.request.urlopen(req, timeout=15) as response:
        res = json.loads(response.read().decode("utf-8"))
        return res.get("response", "")

def call_llm(prompt: str) -> str:
    """
    Route LLM call to OpenAI or Ollama, fallback to Exception if neither configured.
    """
    if OPENAI_API_KEY:
        return call_openai(prompt)
    else:
        return call_ollama(prompt)

def get_deterministic_fallback(raw_diff: str, triggered_rules: List[Dict[str, Any]], ip_findings: List[Dict[str, Any]]) -> Dict[str, str]:
    """
    Generates a highly structured, accurate review based on rules and diff when LLM is unavailable.
    """
    critical_issues = [r for r in triggered_rules if r["severity"] == "critical"]
    high_issues = [r for r in triggered_rules if r["severity"] == "high"]
    medium_issues = [r for r in triggered_rules if r["severity"] == "medium"]
    low_issues = [r for r in triggered_rules if r["severity"] == "low"]
    malicious_ips = [ip for ip in ip_findings if ip["is_malicious"]]

    # 1. Executive Summary
    summary_parts = []
    summary_parts.append("This configuration change has been analyzed programmatically.")
    if triggered_rules:
        summary_parts.append(f"The analysis triggered {len(triggered_rules)} security and configuration compliance rules.")
    else:
        summary_parts.append("No security or compliance rule violations were triggered.")
        
    if malicious_ips:
        summary_parts.append(f"Warning: {len(malicious_ips)} public IP addresses with malicious reputations were detected in the configuration.")

    exec_summary = " ".join(summary_parts)

    # 2. Approval Recommendation
    if critical_issues or malicious_ips:
        recommendation = "Reject"
        rec_details = "The configuration review has been REJECTED due to critical security risks. "
        remediations = []
        for issue in critical_issues:
            remediations.append(f"- Remove permissive Access List widening: {issue['rule_name']}.")
        for ip in malicious_ips:
            remediations.append(f"- Review exposure of malicious IP: {ip['ip']} ({ip['details']}).")
        
        rec_text = rec_details + "\nRemediations required before approval:\n" + "\n".join(remediations)
    elif high_issues:
        recommendation = "Approve with Caveats"
        rec_details = "The configuration change is APPROVED WITH CAVEATS due to high security findings. "
        remediations = []
        for issue in high_issues:
            remediations.append(f"- Replace unencrypted services or weak passwords: {issue['rule_name']}.")
        
        rec_text = rec_details + "\nCaveats to resolve:\n" + "\n".join(remediations)
    elif medium_issues or low_issues:
        recommendation = "Approve with Caveats"
        rec_text = "APPROVED WITH CAVEATS: Please review the warnings relating to routing protocol changes, NAT configurations, or interface changes."
    else:
        recommendation = "Approve"
        rec_text = "APPROVED: The configuration changes adhere to security standards and represent standard changes."

    # 3. AI Risk Analysis
    risk_parts = []
    if triggered_rules:
        risk_parts.append("Rule-based analysis identified the following concerns:")
        for r in triggered_rules:
            risk_parts.append(f"- [{r['severity'].upper()}] {r['rule_name']}: {r['description']}")
            if r.get("matched_lines"):
                lines_str = ", ".join(r["matched_lines"])
                risk_parts.append(f"  Lines: {lines_str}")
    else:
        risk_parts.append("No risk rules were triggered. Config appears to conform to baseline security policies.")
    
    risk_analysis = "\n".join(risk_parts)

    # 4. Reviewer Notes
    notes_parts = [
        "1. Rollout Procedure: Apply during the scheduled maintenance window. Proactively verify route tables and ping critical subnets.",
        "2. Rollback Procedure: If service is interrupted, apply the 'old_config' immediately and verify interface status.",
        "3. Verification: Perform trace route checks and audit firewall logs to verify correct policy enforcement."
    ]
    reviewer_notes = "\n".join(notes_parts)

    return {
        "executive_summary": exec_summary,
        "approval_recommendation": f"Status: {recommendation}\n{rec_text}",
        "ai_risk_analysis": risk_analysis,
        "reviewer_notes": reviewer_notes
    }

def run_agent_workflow(raw_diff: str, triggered_rules: List[Dict[str, Any]], ip_findings: List[Dict[str, Any]]) -> Dict[str, str]:
    """
    Orchestrates the AI review process:
    Agent 1 (Diff Analyzer) -> Agent 2 (Security Reviewer) -> Agent 3 (Approval Generator) -> Coordinator.
    If no LLM connection is available, falls back gracefully to a rule-based deterministic response.
    """
    try:
        # Step 1: Run Diff Analyzer
        diff_prompt = DIFF_ANALYZER_PROMPT.format(raw_diff=raw_diff)
        diff_analysis = call_llm(diff_prompt)
        
        # Step 2: Run Security Reviewer
        rules_str = json.dumps(triggered_rules, indent=2)
        ips_str = json.dumps(ip_findings, indent=2)
        security_prompt = SECURITY_REVIEWER_PROMPT.format(
            change_summary=diff_analysis,
            triggered_rules=rules_str,
            ip_findings=ips_str
        )
        security_findings = call_llm(security_prompt)
        
        # Step 3: Run Approval Generator
        approval_prompt = APPROVAL_GENERATOR_PROMPT.format(
            change_summary=diff_analysis,
            security_findings=security_findings
        )
        approval_output = call_llm(approval_prompt)
        
        # Step 4: Final Coordinator to generate JSON
        coord_prompt = COORDINATOR_PROMPT.format(
            diff_analysis=diff_analysis,
            security_review=security_findings,
            approval_output=approval_output
        )
        final_json_str = call_llm(coord_prompt)
        
        # Parse output JSON
        # Clean potential markdown wrappers e.g. ```json ... ```
        if "```" in final_json_str:
            final_json_str = final_json_str.split("```")[1]
            if final_json_str.startswith("json"):
                final_json_str = final_json_str[4:]
        
        parsed_result = json.loads(final_json_str.strip())
        return {
            "executive_summary": parsed_result.get("executive_summary", ""),
            "approval_recommendation": parsed_result.get("approval_recommendation", ""),
            "ai_risk_analysis": parsed_result.get("ai_risk_analysis", ""),
            "reviewer_notes": parsed_result.get("reviewer_notes", "")
        }
        
    except Exception as e:
        print(f"AI Agent Workflow encountered an error/offline. Running deterministic fallback. Error: {str(e)}")
        # Graceful fallback to rule-based analysis
        return get_deterministic_fallback(raw_diff, triggered_rules, ip_findings)
