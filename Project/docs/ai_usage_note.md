# AI Usage Note - Network Config Diff Reviewer

This document details where Artificial Intelligence (AI) was integrated into the **Network Config Diff Reviewer**, the prompts utilized, workflow constraints, limitations, and guidelines for human-in-the-loop validation.

---

## Where AI is Used

AI is incorporated as a **Multi-Agent Collaboration Workflow** that reviews proposed configuration changes after baseline parsing:

1. **Diff Analyzer Agent (Agent 1):** Takes raw Unified Diffs and breaks down Cisco-style additions, deletions, or modifications into structured structural groups (ACLs, Interfaces, Routing protocols, Security controls).
2. **Security Reviewer Agent (Agent 2):** Takes the structural summary, compares it to rule-based security violations triggered statically (e.g., telnet usage, public communities), cross-checks public IP threat metrics, and rates each issue by severity.
3. **Approval Generator Agent (Agent 3):** Formulates deployment rollout/rollback guidelines, executive summaries for management, and recommends whether to Approve, Approve with Caveats, or Reject the change.
4. **Final Coordinator Agent (Agent 4):** Pools all previous assessments and compiles a standard, valid JSON block that feeds directly into the Postgres/SQLite database, PDF Report engine, and Markdown exports.

---

## Agent Prompt Blueprints

The following core prompts are injected into the LLM context wrapper:

### 1. Diff Analyzer Agent
```markdown
You are a Senior Network Engineer. Your task is to analyze the raw configuration diff between the old configuration and new configuration.
Analyze which lines were added (+), modified, or removed (-).

Categorize the changes into the following groups and summarize them:
1. Access Control Lists (ACLs) / Firewall rules
2. Routing Protocols (BGP, OSPF, static routes, default gateways)
3. Interface and IP assignments
4. Management and Security settings (SSH, Telnet, SNMP, usernames, passwords)
5. Miscellaneous/Other changes
```

### 2. Security Reviewer Agent
```markdown
You are a Senior Network Security Architect. Your task is to assess security risks in the configuration changes.
Use the change summary and the rule-based trigger logs below to determine the security impact.

Identify specific security weaknesses introduced:
- Has security been weakened? (e.g. permissive ACLs, unencrypted protocols, exposed services, weak credentials, bad DNS/routing exit points).
- For any new public IPs found, did the reputation check suggest threat indicators?
```

### 3. Approval Generator Agent
```markdown
You are a Principal Network Architect and Auditor. Your job is to make a final approval recommendation based on the change summary and security risk findings.

Decide on an approval status (Approve, Approve with Caveats, or Reject).
Generate:
1. Executive Summary
2. Approval Recommendation and Remediation steps
3. Reviewer Notes (rollout and rollback guidelines)
```

---

## Limitations & AI Hallucinations

While LLMs are highly effective at reading text configs, they are subject to standard limitations:

1. **Context Window Limitations:** Very large configurations (e.g., >10,000 lines of router data) may exceed the context budget. The system mitigates this by extracting only **changed lines (diffs)** and matching logs rather than raw configs.
2. **Syntax Ambiguities:** Router commands vary widely across hardware vendors (Cisco IOS, Juniper JunOS, Palo Alto PAN-OS). The AI is optimized for Cisco-style syntax and may misinterpret vendor-specific scripts.
3. **Logical Exclusions:** An AI might not realize that a specific WAN route addition alters traffic metrics globally, which could result in asymmetric routing bugs. Statically engineered route tables should be checked.

---

## Human-in-the-Loop Recommendations

AI-generated summaries must serve as **advisory guides** and not automatic deployment triggers. The following validations must be completed by human engineers:

1. **Verify Sandbox Tests:** Configurations should be tested on simulated networks (e.g., GNS3, Cisco Modeling Labs) before live application.
2. **Review Override Logs:** Reviewers should check the `Reviewer Override Panel` on the review details screen to add manual rollout notes or adjust statuses from `Reviewed` to `Approved`.
3. **Audit High/Critical Risks:** Pay close attention to warnings detailing SNMP defaults or telnet configurations.
