import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from backend.app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default="engineer")  # engineer, reviewer, admin
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    reviews = relationship("Review", back_populates="creator", foreign_keys="Review.created_by")
    audit_logs = relationship("AuditLog", back_populates="user")


class UploadedFile(Base):
    __tablename__ = "uploaded_files"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    filename = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_size = Column(Integer, nullable=False)
    sha256 = Column(String(64), nullable=False)
    content = Column(Text, nullable=False)
    uploaded_at = Column(DateTime, default=datetime.utcnow)


class Review(Base):
    __tablename__ = "reviews"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(255), nullable=False)
    status = Column(String(50), default="pending")  # pending, reviewed, approved, rejected
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(50), default="low")  # low, medium, high, critical
    created_by = Column(String(36), ForeignKey("users.id"), nullable=False)
    old_file_id = Column(String(36), ForeignKey("uploaded_files.id"), nullable=True)
    new_file_id = Column(String(36), ForeignKey("uploaded_files.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    creator = relationship("User", back_populates="reviews", foreign_keys=[created_by])
    old_file = relationship("UploadedFile", foreign_keys=[old_file_id])
    new_file = relationship("UploadedFile", foreign_keys=[new_file_id])
    
    diff_result = relationship("DiffResult", back_populates="review", uselist=False, cascade="all, delete-orphan")
    risk_assessment = relationship("RiskAssessment", back_populates="review", uselist=False, cascade="all, delete-orphan")
    approval_report = relationship("ApprovalReport", back_populates="review", uselist=False, cascade="all, delete-orphan")


class DiffResult(Base):
    __tablename__ = "diff_results"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    review_id = Column(String(36), ForeignKey("reviews.id"), nullable=False)
    raw_diff = Column(Text, nullable=False)
    added_count = Column(Integer, default=0)
    removed_count = Column(Integer, default=0)
    modified_count = Column(Integer, default=0)
    diff_json = Column(JSON, nullable=True)  # Detailed line-by-line diff mapping

    review = relationship("Review", back_populates="diff_result")


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    review_id = Column(String(36), ForeignKey("reviews.id"), nullable=False)
    rules_triggered = Column(JSON, default=list)  # Triggered check rules
    ai_risk_analysis = Column(Text, nullable=True)
    ip_reputation_findings = Column(JSON, default=list)

    review = relationship("Review", back_populates="risk_assessment")


class ApprovalReport(Base):
    __tablename__ = "approval_reports"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    review_id = Column(String(36), ForeignKey("reviews.id"), nullable=False)
    executive_summary = Column(Text, nullable=True)
    approval_recommendation = Column(Text, nullable=True)
    reviewer_notes = Column(Text, nullable=True)
    pdf_path = Column(String(512), nullable=True)
    md_path = Column(String(512), nullable=True)

    review = relationship("Review", back_populates="approval_report")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    action = Column(String(255), nullable=False)
    ip_address = Column(String(45), nullable=True)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="audit_logs")
