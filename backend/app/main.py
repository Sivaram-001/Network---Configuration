import os
import time
from datetime import datetime
from collections import defaultdict
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from backend.app.config import ALLOWED_ORIGINS
from backend.app import models, schemas, database, auth, diff, risk_engine, storage
from backend.app.external import reputation
from backend.app.agents import workflow
from backend.app.reports import pdf_gen, md_gen

# Initialize Database tables
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(
    title="Network Config Diff Reviewer API",
    description="Automated analysis and security scoring for router, switch, and firewall configurations.",
    version="1.0.0"
)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom Rate Limiter
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQUESTS = 100
request_history = defaultdict(list)

@app.middleware("http")
async def rate_limiting_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"
    now = time.time()
    
    # Filter out requests older than the window
    request_history[client_ip] = [t for t in request_history[client_ip] if now - t < RATE_LIMIT_WINDOW]
    
    if len(request_history[client_ip]) >= RATE_LIMIT_MAX_REQUESTS:
        return Response(
            content=json.dumps({"detail": "Rate limit exceeded. Please try again later."}),
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            media_type="application/json"
        )
    
    request_history[client_ip].append(now)
    return await call_next(request)

# Secure Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com;"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# Database log helper
def log_audit(db: Session, user_id: Optional[str], action: str, ip_address: Optional[str], details: str):
    log = models.AuditLog(
        user_id=user_id,
        action=action,
        ip_address=ip_address,
        details=details
    )
    db.add(log)
    db.commit()

# --- Auth Endpoints ---

@app.post("/auth/register", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_in: schemas.UserRegister, db: Session = Depends(database.get_db), request: Request = None):
    db_user = db.query(models.User).filter(models.User.email == user_in.email).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    if user_in.role not in ["engineer", "reviewer", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role configuration. Allowed roles: engineer, reviewer, admin"
        )
        
    hashed_pwd = auth.get_password_hash(user_in.password)
    user = models.User(
        email=user_in.email,
        hashed_password=hashed_pwd,
        role=user_in.role
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    
    client_ip = request.client.host if request else "127.0.0.1"
    log_audit(db, user.id, "USER_REGISTER", client_ip, f"User registered with role: {user.role}")
    
    return user

@app.post("/auth/login", response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(database.get_db), request: Request = None):
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = auth.create_access_token(data={"sub": user.email, "role": user.role})
    
    client_ip = request.client.host if request else "127.0.0.1"
    log_audit(db, user.id, "USER_LOGIN", client_ip, f"User successfully authenticated.")
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": user.role,
        "email": user.email
    }

# --- File Upload Endpoints ---

@app.post("/upload", response_model=schemas.UploadResponse)
def upload_config(
    file: UploadFile = File(...),
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.require_engineer),
    request: Request = None
):
    # Extension validation
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in [".txt", ".cfg", ".conf"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported file extension. Allowed extensions are: .txt, .cfg, .conf"
        )
        
    # Read file content and validate empty files
    try:
        content_bytes = file.file.read()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not read uploaded file contents."
        )
        
    if not content_bytes or len(content_bytes.strip()) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty configuration files are not allowed."
        )
        
    # File size validation (Max 2MB)
    if len(content_bytes) > 2 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File size exceeds the 2MB limit."
        )

    # Save to disk
    file_info = storage.storage_manager.save_file(content_bytes, file.filename)
    
    # Save to database
    db_file = models.UploadedFile(
        id=file_info["id"],
        filename=file_info["filename"],
        file_path=file_info["file_path"],
        file_size=file_info["file_size"],
        sha256=file_info["sha256"],
        content=file_info["content"]
    )
    db.add(db_file)
    db.commit()
    db.refresh(db_file)
    
    client_ip = request.client.host if request else "127.0.0.1"
    log_audit(db, current_user.id, "FILE_UPLOAD", client_ip, f"Uploaded file: {db_file.filename} (Size: {db_file.file_size} bytes)")
    
    return db_file

# --- Analysis Endpoints ---

@app.post("/analyze", response_model=schemas.ReviewDetailResponse)
def analyze_configs(
    payload: schemas.ReviewCreate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.require_engineer),
    request: Request = None
):
    # Fetch files
    new_file = db.query(models.UploadedFile).filter(models.UploadedFile.id == payload.new_file_id).first()
    if not new_file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="New config file not found"
        )
        
    old_file = None
    old_content = ""
    if payload.old_file_id:
        old_file = db.query(models.UploadedFile).filter(models.UploadedFile.id == payload.old_file_id).first()
        if not old_file:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Old config file not found"
            )
        old_content = old_file.content

    # 1. Generate line-by-line diff
    diff_res = diff.generate_config_diff(old_content, new_file.content)
    
    # 2. Risk detection rules & scoring
    rules_res = risk_engine.analyze_config_risks(diff_res["diff_json"])
    
    # 3. Public IP Reputation check
    ip_findings = reputation.analyze_config_ips(new_file.content)
    
    # 4. AI Agent Workflow
    ai_review = workflow.run_agent_workflow(
        raw_diff=diff_res["raw_diff"],
        triggered_rules=rules_res["rules_triggered"],
        ip_findings=ip_findings
    )
    
    # Create Review Record
    review = models.Review(
        title=payload.title,
        status="reviewed" if rules_res["risk_score"] > 20 else "approved",
        risk_score=rules_res["risk_score"],
        risk_level=rules_res["risk_level"],
        created_by=current_user.id,
        old_file_id=payload.old_file_id,
        new_file_id=payload.new_file_id
    )
    db.add(review)
    db.commit()
    db.refresh(review)
    
    # Save DiffResult
    db_diff = models.DiffResult(
        review_id=review.id,
        raw_diff=diff_res["raw_diff"],
        added_count=diff_res["added_count"],
        removed_count=diff_res["removed_count"],
        modified_count=diff_res["modified_count"],
        diff_json=diff_res["diff_json"]
    )
    db.add(db_diff)
    
    # Save RiskAssessment
    db_risk = models.RiskAssessment(
        review_id=review.id,
        rules_triggered=rules_res["rules_triggered"],
        ai_risk_analysis=ai_review.get("ai_risk_analysis"),
        ip_reputation_findings=ip_findings
    )
    db.add(db_risk)
    
    # Build Report Exporters
    pdf_path = storage.storage_manager.get_report_path(review.id, "pdf")
    md_path = storage.storage_manager.get_report_path(review.id, "md")
    
    pdf_gen.generate_pdf_report(
        output_path=pdf_path,
        review_title=review.title,
        status=review.status,
        risk_score=review.risk_score,
        risk_level=review.risk_level,
        created_at=review.created_at,
        creator_email=current_user.email,
        stats=diff_res["diff_json"]["statistics"],
        rules_triggered=rules_res["rules_triggered"],
        ip_findings=ip_findings,
        executive_summary=ai_review.get("executive_summary", ""),
        approval_recommendation=ai_review.get("approval_recommendation", ""),
        ai_risk_analysis=ai_review.get("ai_risk_analysis", ""),
        reviewer_notes=ai_review.get("reviewer_notes", "")
    )
    
    md_gen.generate_markdown_report(
        output_path=md_path,
        review_title=review.title,
        status=review.status,
        risk_score=review.risk_score,
        risk_level=review.risk_level,
        created_at=review.created_at,
        creator_email=current_user.email,
        stats=diff_res["diff_json"]["statistics"],
        rules_triggered=rules_res["rules_triggered"],
        ip_findings=ip_findings,
        executive_summary=ai_review.get("executive_summary", ""),
        approval_recommendation=ai_review.get("approval_recommendation", ""),
        ai_risk_analysis=ai_review.get("ai_risk_analysis", ""),
        reviewer_notes=ai_review.get("reviewer_notes", "")
    )
    
    # Save Approval Report
    db_report = models.ApprovalReport(
        review_id=review.id,
        executive_summary=ai_review.get("executive_summary"),
        approval_recommendation=ai_review.get("approval_recommendation"),
        reviewer_notes=ai_review.get("reviewer_notes"),
        pdf_path=pdf_path,
        md_path=md_path
    )
    db.add(db_report)
    db.commit()
    
    client_ip = request.client.host if request else "127.0.0.1"
    log_audit(db, current_user.id, "RUN_ANALYSIS", client_ip, f"Analyzed configurations for: {review.title} (Risk: {review.risk_score} - {review.risk_level})")
    
    return {
        "review": review,
        "old_filename": old_file.filename if old_file else "None (Initial Baseline)",
        "new_filename": new_file.filename,
        "diff_result": db_diff,
        "risk_assessment": db_risk,
        "approval_report": db_report
    }

# --- Review Routing ---

@app.get("/reviews", response_model=List[schemas.ReviewResponse])
def list_reviews(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.require_engineer)
):
    # Engineers see their own. Reviewers and admins see all.
    if current_user.role in ["reviewer", "admin"]:
        return db.query(models.Review).order_by(models.Review.created_at.desc()).all()
    return db.query(models.Review).filter(models.Review.created_by == current_user.id).order_by(models.Review.created_at.desc()).all()

@app.get("/review/{id}", response_model=schemas.ReviewDetailResponse)
def get_review_detail(
    id: str,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.require_engineer)
):
    review = db.query(models.Review).filter(models.Review.id == id).first()
    if not review:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Review not found"
        )
        
    # Check permissions
    if current_user.role == "engineer" and review.created_by != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to view this review"
        )
        
    old_file = db.query(models.UploadedFile).filter(models.UploadedFile.id == review.old_file_id).first() if review.old_file_id else None
    new_file = db.query(models.UploadedFile).filter(models.UploadedFile.id == review.new_file_id).first()
    
    return {
        "review": review,
        "old_filename": old_file.filename if old_file else "None (Initial Baseline)",
        "new_filename": new_file.filename if new_file else "Deleted File",
        "diff_result": review.diff_result,
        "risk_assessment": review.risk_assessment,
        "approval_report": review.approval_report
    }

@app.post("/review/{id}", response_model=schemas.ReviewResponse)
def update_review_decision(
    id: str,
    payload: schemas.ReviewUpdate,
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.require_reviewer),
    request: Request = None
):
    review = db.query(models.Review).filter(models.Review.id == id).first()
    if not review:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Review not found"
        )
        
    if payload.status not in ["approved", "rejected", "reviewed"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid status. Status can be: approved, rejected, reviewed"
        )
        
    review.status = payload.status
    
    if review.approval_report and payload.reviewer_notes:
        review.approval_report.reviewer_notes = payload.reviewer_notes
        
    db.commit()
    db.refresh(review)
    
    client_ip = request.client.host if request else "127.0.0.1"
    log_audit(db, current_user.id, "REVIEW_DECISION", client_ip, f"Updated review {review.id} status to: {review.status}")
    
    return review

# --- Reports Serving ---

@app.get("/report/{id}")
def download_report(
    id: str,
    format: str = "pdf",
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.require_engineer)
):
    review = db.query(models.Review).filter(models.Review.id == id).first()
    if not review:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Review not found"
        )
        
    # Check permissions
    if current_user.role == "engineer" and review.created_by != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions to download this report"
        )
        
    report = review.approval_report
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report files not found for this review"
        )
        
    if format.lower() == "pdf":
        file_path = report.pdf_path
        media_type = "application/pdf"
        filename = f"network_review_{review.id}.pdf"
    elif format.lower() == "md" or format.lower() == "markdown":
        file_path = report.md_path
        media_type = "text/markdown"
        filename = f"network_review_{review.id}.md"
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid format. Supported options: pdf, md"
        )
        
    if not file_path or not os.path.exists(file_path):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report file in format {format} is missing from storage."
        )
        
    return FileResponse(
        path=file_path,
        media_type=media_type,
        filename=filename
    )

# --- Dashboard API ---

@app.get("/dashboard", response_model=schemas.DashboardResponse)
def get_dashboard_summary(
    db: Session = Depends(database.get_db),
    current_user: models.User = Depends(auth.require_engineer)
):
    # Build filter
    base_query = db.query(models.Review)
    if current_user.role == "engineer":
        base_query = base_query.filter(models.Review.created_by == current_user.id)
        
    reviews = base_query.all()
    
    total = len(reviews)
    high_risk = len([r for r in reviews if r.risk_level in ["high", "critical"]])
    approved = len([r for r in reviews if r.status == "approved"])
    pending = len([r for r in reviews if r.status in ["pending", "reviewed"]])
    
    stats = {
        "total_reviews": total,
        "high_risk_reviews": high_risk,
        "approved_reviews": approved,
        "pending_reviews": pending
    }
    
    # Recent activity
    recent_reviews = base_query.order_by(models.Review.updated_at.desc()).limit(10).all()
    recent_activity = []
    for r in recent_reviews:
        recent_activity.append({
            "review_id": r.id,
            "title": r.title,
            "status": r.status,
            "risk_score": r.risk_score,
            "risk_level": r.risk_level,
            "updated_at": r.updated_at
        })
        
    return {
        "stats": stats,
        "recent_activity": recent_activity
    }
