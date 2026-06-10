import os
import io
import sys
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add project root to python path to access backend logic
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from backend.app import models, database
from backend.app.main import app

from sqlalchemy.pool import StaticPool

# Database Override for Testing (In-Memory SQLite)
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, 
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

# Override dependency
app.dependency_overrides[database.get_db] = override_get_db

# Create test tables
models.Base.metadata.create_all(bind=engine)

client = TestClient(app)

def test_full_api_workflow():
    # 1. Register a user
    register_payload = {
        "email": "engineer@test.com",
        "password": "testpassword123",
        "role": "engineer"
    }
    res_register = client.post("/auth/register", json=register_payload)
    assert res_register.status_code == 201
    assert res_register.json()["email"] == "engineer@test.com"
    assert res_register.json()["role"] == "engineer"
    
    # 2. Login
    login_payload = {
        "username": "engineer@test.com",
        "password": "testpassword123"
    }
    res_login = client.post("/auth/login", data=login_payload)
    assert res_login.status_code == 200
    token_data = res_login.json()
    assert "access_token" in token_data
    assert token_data["role"] == "engineer"
    
    token = token_data["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # 3. Test Protected Upload (Fail without auth)
    res_upload_fail = client.post("/upload", files={"file": ("old.cfg", b"test")})
    assert res_upload_fail.status_code == 401
    
    # 4. Upload configurations
    old_config_text = b"interface GigabitEthernet0/1\n shutdown\n!"
    new_config_text = b"interface GigabitEthernet0/1\n no shutdown\n!"
    
    res_upload_old = client.post(
        "/upload", 
        files={"file": ("old.cfg", io.BytesIO(old_config_text))},
        headers=headers
    )
    assert res_upload_old.status_code == 200
    old_file_id = res_upload_old.json()["id"]
    
    res_upload_new = client.post(
        "/upload", 
        files={"file": ("new.cfg", io.BytesIO(new_config_text))},
        headers=headers
    )
    assert res_upload_new.status_code == 200
    new_file_id = res_upload_new.json()["id"]
    
    # 5. Run Analysis
    analyze_payload = {
        "title": "Port Activation Review",
        "old_file_id": old_file_id,
        "new_file_id": new_file_id
    }
    res_analyze = client.post("/analyze", json=analyze_payload, headers=headers)
    assert res_analyze.status_code == 200
    analysis_data = res_analyze.json()
    assert analysis_data["review"]["title"] == "Port Activation Review"
    review_id = analysis_data["review"]["id"]
    
    # 6. Fetch reviews list
    res_reviews = client.get("/reviews", headers=headers)
    assert res_reviews.status_code == 200
    assert len(res_reviews.json()) >= 1
    
    # 7. Get review detail
    res_detail = client.get(f"/review/{review_id}", headers=headers)
    assert res_detail.status_code == 200
    detail_data = res_detail.json()
    assert detail_data["old_filename"] == "old.cfg"
    assert detail_data["new_filename"] == "new.cfg"
    assert "diff_result" in detail_data
    assert "risk_assessment" in detail_data
    
    # 8. Fetch dashboard
    res_dashboard = client.get("/dashboard", headers=headers)
    assert res_dashboard.status_code == 200
    assert res_dashboard.json()["stats"]["total_reviews"] >= 1
    
    # 9. Download reports (PDF and MD)
    res_pdf = client.get(f"/report/{review_id}?format=pdf", headers=headers)
    assert res_pdf.status_code == 200
    assert res_pdf.headers["content-type"].startswith("application/pdf")
    
    res_md = client.get(f"/report/{review_id}?format=md", headers=headers)
    assert res_md.status_code == 200
    assert res_md.headers["content-type"].startswith("text/markdown")
