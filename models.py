"""Database tables. SQLAlchemy turns these Python classes into SQL tables,
so the same code works on SQLite (local) and Azure SQL (cloud)."""
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

ROLES = ("admin", "investigator", "auditor")


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    full_name = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="investigator")
    is_active_user = db.Column(db.Boolean, nullable=False, default=True)
    failed_logins = db.Column(db.Integer, nullable=False, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    @property
    def is_active(self):  # Flask-Login uses this to block disabled accounts
        return self.is_active_user


class Evidence(db.Model):
    __tablename__ = "evidence"
    id = db.Column(db.Integer, primary_key=True)
    evidence_no = db.Column(db.String(30), unique=True, nullable=True)
    case_number = db.Column(db.String(50), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    original_filename = db.Column(db.String(255), nullable=False)
    content_type = db.Column(db.String(120), nullable=True)
    size_bytes = db.Column(db.BigInteger, nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    storage_key = db.Column(db.String(300), nullable=False, unique=True)
    status = db.Column(db.String(20), nullable=False, default="Unverified")  # Intact / Tampered / Error / Unverified
    last_verified_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    custodian_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    uploaded_by = db.relationship("User", foreign_keys=[uploaded_by_id])
    custodian = db.relationship("User", foreign_keys=[custodian_id])
    custody_events = db.relationship("CustodyEvent", backref="evidence", order_by="CustodyEvent.id")
    verifications = db.relationship("VerificationRecord", backref="evidence", order_by="VerificationRecord.id.desc()")


class CustodyEvent(db.Model):
    __tablename__ = "custody_events"
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey("evidence.id"), nullable=False, index=True)
    action = db.Column(db.String(20), nullable=False)  # REGISTERED / TRANSFER
    from_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    to_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    reason = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    from_user = db.relationship("User", foreign_keys=[from_user_id])
    to_user = db.relationship("User", foreign_keys=[to_user_id])


class VerificationRecord(db.Model):
    __tablename__ = "verification_records"
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey("evidence.id"), nullable=False, index=True)
    verified_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    expected_hash = db.Column(db.String(64), nullable=False)
    computed_hash = db.Column(db.String(64), nullable=True)
    result = db.Column(db.String(10), nullable=False)  # PASS / FAIL / ERROR
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    verified_by = db.relationship("User", foreign_keys=[verified_by_id])


class AuditLog(db.Model):
    """Append-only log. Each row stores a hash that includes the previous row's hash,
    so editing or deleting any old row breaks the chain (tamper-evident)."""
    __tablename__ = "audit_logs"
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.String(19), nullable=False)  # stored as text so the hash never changes
    username = db.Column(db.String(64), nullable=False)
    action = db.Column(db.String(40), nullable=False, index=True)
    target = db.Column(db.String(200), nullable=False, default="")
    details = db.Column(db.String(500), nullable=False, default="")
    ip_address = db.Column(db.String(64), nullable=False, default="")
    prev_hash = db.Column(db.String(64), nullable=False)
    entry_hash = db.Column(db.String(64), nullable=False)
