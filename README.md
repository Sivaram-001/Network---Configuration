# Network Config Diff Reviewer

**Network Config Diff Reviewer** is a production-grade full-stack compliance auditing application. It automates the review of network configuration scripts (routers, switches, firewalls, ACLs), highlights visual line-by-line diffs (green/red/yellow), scans configurations for security vulnerabilities, evaluates reputation scores on public IPv4 addresses, runs a Multi-Agent AI Review Workflow, and generates downloadable PDF and Markdown reports.

---

## 🏗️ System Architecture

```
                       +---------------------------------------+
                       |             Next.js Web UI            |
                       |          (Next.js 15, Tailwind)       |
                       +-------------------+-------------------+
                                           |
                                  CORS JWT | API Queries
                                           v
                       +-------------------+-------------------+
                       |             FastAPI API               |
                       |       (Python, SQLAlchemy ORM)        |
                       +-----+-------------+-------------+-----+
                             |             |             |
                             v             v             v
                    +--------+-----+ +-----+--------+ +--+----------+
                    | SQLite/Postgres| | Local Storage | | MCP Stdio   |
                    | (Reviews, Logs)| | (Configs, PDF) | | RPC Server  |
                    +--------------+-+ +------------+ +-------------+
                                   |
                                   v  AI Agents Workflow
                    +--------------+----------------------------+
                    | Agent 1: Diff Analyzer                     |
                    | Agent 2: Security Reviewer (Static Rules)  |
                    | Agent 3: Approval Package Generator        |
                    | Agent 4: Final Coordinator (JSON parser)   |
                    +--------------------+-----------------------+
                                         |
                                         v API Calls
                            +------------+------------+
                            | OpenAI API / Local Ollama|
                            +-------------------------+
```

---

## 🛠️ Tech Stack

- **Frontend:** Next.js 15 (App Router), TypeScript, Tailwind CSS, Lucide icons, native fetch wrapper.
- **Backend:** FastAPI (Python), Uvicorn ASGI.
- **Database:** PostgreSQL (with SQLAlchemy ORM), automatic database schema initialization. Graceful automatic fallback to SQLite (`network_reviewer.db`) for immediate offline testing.
- **AI Agent Engine:** OpenAI API (gpt-4o-mini) and Local Ollama (llama3) support. Features a deterministic rule-based analysis fallback when offline.
- **PDF Compiler:** ReportLab.
- **Markdown Exporter:** Python Markdown.
- **Testing Suite:** Pytest (100% test coverage with 14 passed cases).
- **Orchestration:** Docker, Docker Compose.
- **MCP Integration:** Stdio-based JSON-RPC Model Context Protocol server.

---

## 🚀 Getting Started

### Option 1: One-Command Startup (Docker Compose)
To run the entire suite (Postgres database, local Ollama, FastAPI backend, and Next.js frontend web app):

1. **Start the services:**
   ```bash
   docker-compose up --build
   ```
2. **Access the Web Interface:** Open [http://localhost:3000](http://localhost:3000) in your browser.
3. **API Documentation:** Interactive docs will be active at [http://localhost:8000/docs](http://localhost:8000/docs).

### Option 2: Running Locally

#### 1. Start Backend API Server
1. Navigate to the workspace and install backend requirements:
   ```bash
   pip install -r backend/requirements.txt
   ```
2. Start the FastAPI server locally using Uvicorn:
   ```bash
   python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
   ```
   *(The backend will automatically initialize the local SQLite database file `backend/network_reviewer.db`)*

#### 2. Start Next.js Frontend
1. Navigate to `frontend/` directory and install packages:
   ```bash
   cd frontend
   npm install
   ```
2. Launch the Next.js development server:
   ```bash
   npm run dev
   ```
3. Open [http://localhost:3000](http://localhost:3000).

---

## 🧪 Running Automated Tests

A comprehensive suite of 14 tests is provided verifying all core logic.

1. Ensure requirements are installed:
   ```bash
   pip install -r backend/requirements.txt httpx
   ```
2. Execute pytest:
   ```bash
   python -m pytest tests
   ```

---

## 📁 Sample Configurations
We provide baseline and proposed configuration files inside the [sample_data/](file:///c:/Users/Asus/Desktop/Network%20config/sample_data/) folder:

- **`old_config.txt`:** Secure baseline with restrictive ACL rules, secure management (SSH only), and interface shutdown states.
- **`new_config.txt`:** Proposed script introducing critical security exposures:
  - ACL Widening: `permit ip any any`
  - Exposed ports: `permit tcp any any eq 23`
  - Cleartext Telnet enabled under line vty
  - SNMP community changed to `public`
  - Default route forwarding exit points to a threat-flagged public IP: `198.51.100.42`
  - Plaintext username password credentials
  - Physical ports enabled: `no shutdown`

---

## 🗺️ API Endpoints Map

- **Authentication:**
  - `POST /auth/register`: Create accounts with Engineer, Reviewer, or Admin roles.
  - `POST /auth/login`: Retrieve JWT access tokens.
- **Config Management:**
  - `POST /upload`: Uploads and hashes router configurations (.txt, .cfg, .conf up to 2MB).
  - `POST /analyze`: Generates line-by-line diffs, runs risk matching, extracts IPs, runs AI workflows, and builds reports.
- **Reviews & Exporters:**
  - `GET /reviews`: Retrieve list of review history (Engineers see their own, Reviewers/Admins see all).
  - `GET /review/{id}`: Detailed diff, risk logs, and recommendations data.
  - `POST /review/{id}`: Auditing decision updates (Approve/Reject) and note overlays.
  - `GET /report/{id}?format=pdf|md`: Serves downloadable PDF and Markdown review packets.
- **Dashboard:**
  - `GET /dashboard`: Gathers summary metrics and recent reviews list.

---

## 🛠️ Model Context Protocol (MCP) Server

The application implements an **MCP Server** (`mcp-server/mcp_server.py`) enabling LLMs to review configurations natively.

Exposed Tools:
1. **`generate_diff`:** Compares two configurations and returns line diff outputs.
2. **`risk_review`:** Scans a configuration diff for policy violations and returns a security score.
3. **`analyze_config`:** Audits a single configuration script for insecure lines and extracts public IPs.
4. **`generate_report`:** Combines the entire pipeline (diff, risks, threat IP checks, and AI agent workflow) into an aggregated JSON response.

To launch the MCP server:
```bash
python mcp-server/mcp_server.py
```
*(MCP communicates via standard input/output (stdio) using JSON-RPC 2.0 messages)*
