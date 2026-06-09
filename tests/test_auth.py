import sys
from pathlib import Path
import jwt

# Add project root to python path to access backend logic
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from backend.app.auth import verify_password, get_password_hash, create_access_token
from backend.app.config import JWT_SECRET, JWT_ALGORITHM

def test_password_hashing():
    pwd = "secretpassword123"
    hashed = get_password_hash(pwd)
    
    assert hashed != pwd
    assert verify_password(pwd, hashed) is True
    assert verify_password("wrongpassword", hashed) is False

def test_access_token_creation():
    data = {"sub": "engineer@enterprise.internal", "role": "engineer"}
    token = create_access_token(data)
    
    # Decode token and verify claims
    payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    assert payload["sub"] == "engineer@enterprise.internal"
    assert payload["role"] == "engineer"
    assert "exp" in payload
