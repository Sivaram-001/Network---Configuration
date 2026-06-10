from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional, Any, Dict
from datetime import datetime

# Auth Schemas
class UserRegister(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)
    role: str = "engineer" # engineer, reviewer, admin

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    email: EmailStr
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    email: str

class TokenData(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = None

# File Schemas
class UploadResponse(BaseModel):
    id: str
    filename: str
    file_size: int
    sha256: str
    uploaded_at: datetime

    class Config:
        from_attributes = True

# Diff Schemas
class DiffLine(BaseModel):
    type: str  # "added", "removed", "modified", "unchanged"
    content: str
    old_lineno: Optional[int] = None
    new_lineno: Optional[int] = None

class DiffBlock(BaseModel):
    change_type: str  # "acl", "route", "firewall", "general", etc.
    lines: List[DiffLine]

class DiffResultResponse(BaseModel):
    raw_diff: str
    added_count: int
    removed_count: int
    modified_count: int
    diff_json: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True

# Risk Schemas
class RiskRuleTriggered(BaseModel):
    rule_name: str
    severity: str # low, medium, high, critical
    description: str
    matched_lines: List[str]

class IPReputationFinding(BaseModel):
    ip: str
    reputation_score: int
    is_malicious: bool
    details: str

class RiskAssessmentResponse(BaseModel):
    rules_triggered: List[Dict[str, Any]]
    ai_risk_analysis: Optional[str] = None
    ip_reputation_findings: List[Dict[str, Any]]

    class Config:
        from_attributes = True

# Approval & Report Schemas
class ApprovalReportResponse(BaseModel):
    executive_summary: Optional[str] = None
    approval_recommendation: Optional[str] = None
    reviewer_notes: Optional[str] = None
    pdf_path: Optional[str] = None
    md_path: Optional[str] = None

    class Config:
        from_attributes = True

# Review Schemas
class ReviewCreate(BaseModel):
    title: str
    old_file_id: Optional[str] = None
    new_file_id: str

class ReviewUpdate(BaseModel):
    status: str
    reviewer_notes: Optional[str] = None

class ReviewResponse(BaseModel):
    id: str
    title: str
    status: str
    risk_score: int
    risk_level: str
    created_by: str
    old_file_id: Optional[str] = None
    new_file_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class ReviewDetailResponse(BaseModel):
    review: ReviewResponse
    old_filename: Optional[str] = None
    new_filename: Optional[str] = None
    diff_result: Optional[DiffResultResponse] = None
    risk_assessment: Optional[RiskAssessmentResponse] = None
    approval_report: Optional[ApprovalReportResponse] = None

    class Config:
        from_attributes = True

# Dashboard Schema
class DashboardCard(BaseModel):
    total_reviews: int
    high_risk_reviews: int
    approved_reviews: int
    pending_reviews: int

class RecentActivity(BaseModel):
    review_id: str
    title: str
    status: str
    risk_score: int
    risk_level: str
    updated_at: datetime

class DashboardResponse(BaseModel):
    stats: DashboardCard
    recent_activity: List[RecentActivity]

# Audit Log Schema
class AuditLogResponse(BaseModel):
    id: str
    action: str
    details: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: datetime
    email: Optional[str] = None

    class Config:
        from_attributes = True
