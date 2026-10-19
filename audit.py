"""Tamper-evident audit logging (hash chain) and role-based access control helpers."""
import hashlib
from functools import wraps
from flask import request, abort
from flask_login import current_user, login_required
from models import db, AuditLog, utcnow

GENESIS = "0" * 64


def _hash(prev, ts, username, action, target, details, ip):
    raw = "|".join([prev, ts, username, action, target, details, ip])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def log(action, target="", details="", username=None):
    if username is None:
        username = current_user.username if current_user.is_authenticated else "anonymous"
    ip = (request.remote_addr or "")[:64] if request else ""
    last = AuditLog.query.order_by(AuditLog.id.desc()).first()
    prev = last.entry_hash if last else GENESIS
    ts = utcnow().strftime("%Y-%m-%dT%H:%M:%S")
    target, details = str(target)[:200], str(details)[:500]
    entry = AuditLog(timestamp=ts, username=username, action=action, target=target,
                     details=details, ip_address=ip, prev_hash=prev,
                     entry_hash=_hash(prev, ts, username, action, target, details, ip))
    db.session.add(entry)
    db.session.commit()


def verify_chain():
    """Returns (ok, total_rows, first_broken_id)."""
    prev, total = GENESIS, 0
    for row in AuditLog.query.order_by(AuditLog.id).all():
        total += 1
        expected = _hash(row.prev_hash, row.timestamp, row.username, row.action,
                         row.target, row.details, row.ip_address)
        if row.prev_hash != prev or row.entry_hash != expected:
            return False, total, row.id
        prev = row.entry_hash
    return True, total, None


def roles_required(*roles):
    """Decorator: user must be logged in AND have one of the given roles."""
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if current_user.role not in roles:
                log("ACCESS_DENIED", target=request.path, details=f"role={current_user.role}")
                abort(403)
            return view(*args, **kwargs)
        return login_required(wrapper)
    return decorator
