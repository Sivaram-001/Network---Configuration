# Test Cases Document - Network Config Diff Reviewer

This document details the test suites created for verifying the backend computations, endpoints, and algorithms of the **Network Config Diff Reviewer** application.

---

## Test Suites & Coverage Summary

The backend contains a complete suite of unit and integration tests located under `tests/` directory:

| Test File | Target Module | Scope |
| :--- | :--- | :--- |
| `tests/test_diff_engine.py` | `backend/app/diff.py` | Line-by-line diffing, additions, removals, and modifications count. |
| `tests/test_risk_engine.py` | `backend/app/risk_engine.py` | Pattern matching rules, risk scores, and risk level thresholds. |
| `tests/test_reputation.py` | `backend/app/external/reputation.py` | IP extraction regex, private filters, and mock reputation scoring. |
| `tests/test_report_generator.py` | `backend/app/reports/` | PDF compilation (ReportLab) and Markdown formatting. |
| `tests/test_agents.py` | `backend/app/agents/` | Multi-agent state orchestration and deterministic rule fallbacks. |
| `tests/test_auth.py` | `backend/app/auth.py` | Password encryption, token signatures, and role validations. |
| `tests/test_api.py` | `backend/app/main.py` | Integration testing of FastAPI endpoints using `TestClient` and `StaticPool`. |

---

## Detailed Test Cases Description

### 1. Diff Engine (`test_diff_engine.py`)
- **`test_generate_config_diff_basic`**: Asserts that comparing a baseline containing `shutdown` with a proposed file containing `no shutdown` registers 1 modified line and 1 added line. Validates that line numbers match the structural inputs.

### 2. Risk Engine (`test_risk_engine.py`)
- **`test_risk_engine_low_risk`**: Asserts that basic descriptions or comments result in a risk score of 0 (Low).
- **`test_risk_engine_critical_acl_widening`**: Verifies that adding permissive ACL statements (`permit ip any any`) flags a score of 40 (Medium).
- **`test_risk_engine_multiple_vulns`**: Runs a stress test with multiple vulnerabilities (telnet, public SNMP, plaintext passwords). Asserts that the cumulative score is correctly capped at 100 (Critical).

### 3. IP Reputation (`test_reputation.py`)
- **`test_extract_ips_filters_private`**: Asserts that public addresses (like `8.8.8.8`) are successfully gathered from configuration text, while RFC 1918 private subnets are ignored.
- **`test_ip_reputation_safe`**: Asserts that a safe public IP (like `8.8.8.8`) returns a score of 0.
- **`test_ip_reputation_malicious`**: Asserts that querying a flagged mock IP (like `198.51.100.42`) returns a score of 85 and is marked `is_malicious=True`.

### 4. Report Generators (`test_report_generator.py`)
- **`test_report_compilation_and_existence`**: Feeds mock data into the ReportLab PDF compiler and Markdown exporter. Asserts that files are created on disk and have non-zero sizes, and verifies formatting.

### 5. AI Agent Workflow (`test_agents.py`)
- **`test_deterministic_fallback_no_vulns`**: Asserts that when offline, the generator correctly flags "Approved" if no rules are violated.
- **`test_deterministic_fallback_critical_vulns`**: Verifies that critical rule violations trigger a status of "Reject" in the fallback recommendations.
- **`test_run_agent_workflow_offline`**: Asserts that the main orchestrator catches connection timeouts gracefully and redirects execution to the fallback pipeline.

### 6. Authentication (`test_auth.py`)
- **`test_password_hashing`**: Asserts that native bcrypt hashes plain passwords and correctly verifies valid vs invalid passwords.
- **`test_access_token_creation`**: Encodes role claims in a JWT, decodes it, and asserts that TLD claims match the tokens.

### 7. API Endpoints (`test_api.py`)
- **`test_full_api_workflow`**: Overrides the database with an in-memory SQLite static connection. Executes the following sequential flow:
  1. Registers user (`/auth/register`)
  2. Fetches JWT (`/auth/login`)
  3. Verifies authorization guards on `/upload`
  4. Uploads old and new configuration scripts
  5. Requests analysis `/analyze`
  6. Fetches reviews database `/reviews` and dashboard metrics `/dashboard`
  7. Downloads PDF and Markdown reports (`/report/{id}`)
  
---

## Running Backend Test Suite

To run all backend tests locally, execute:
```bash
python -m pytest tests
```
All 14 tests will execute and pass, verifying full backend compliance.
