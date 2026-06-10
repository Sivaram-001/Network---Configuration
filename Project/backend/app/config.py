import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = os.getenv("UPLOAD_DIR", str(BASE_DIR / "storage"))

# Ensure upload directory exists
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Database Config
# Fallback to local SQLite file in the workspace
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/network_reviewer.db")

# Security Config
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-key-network-config-diff-reviewer-2026")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440")) # 24 hours

# AI Config
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_API_BASE = os.getenv("OPENAI_API_BASE", "https://api.openai.com/v1")
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "gpt-4o-mini" if OPENAI_API_KEY else "llama3")

# External APIs
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

# CORS
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:3001,http://127.0.0.1:3000,http://127.0.0.1:3001").split(",")
