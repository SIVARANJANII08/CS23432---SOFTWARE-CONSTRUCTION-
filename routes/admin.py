from flask import Blueprint, render_template, request, redirect, url_for, flash, abort
from flask_login import current_user
from werkzeug.security import generate_password_hash
from models import db, User, AuditLog, ROLES
from audit import log, roles_required, verify_chain

bp = Blueprint("admin", __name__)


def _password_ok(pw):
    return len(pw) >= 8 and any(c.isalpha() for c in pw) and any(c.isdigit() for c in pw)


@bp.route("/admin/users")
@roles_required("admin")
def users():
    return render_template("users.html", users=User.query.order_by(User.id).all(), roles=ROLES)


@bp.route("/admin/users/new", methods=["POST"])
@roles_required("admin")
def create_user():
    username = request.form.get("username", "").strip()
    full_name = request.form.get("full_name", "").strip()
    role = request.form.get("role", "")
    password = request.form.get("password", "")
    if not username or not full_name or role not in ROLES:
        flash("Username, full name and a valid role are required.", "error")
    elif User.query.filter_by(username=username).first():
        flash("That username is already taken.", "error")
    elif not _password_ok(password):
        flash("Password must be at least 8 characters and include a letter and a digit.", "error")
    else:
        db.session.add(User(username=username, full_name=full_name, role=role,
                            password_hash=generate_password_hash(password)))
        db.session.commit()
        log("USER_CREATED", target=username, details=f"role={role}")
        flash(f"User '{username}' created.", "ok")
    return redirect(url_for("admin.users"))


@bp.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@roles_required("admin")
def toggle_user(user_id):
    user = db.session.get(User, user_id) or abort(404)
    if user.id == current_user.id:
        flash("You cannot disable your own account.", "error")
    else:
        user.is_active_user = not user.is_active_user
        db.session.commit()
        log("USER_ENABLED" if user.is_active_user else "USER_DISABLED", target=user.username)
        flash(f"User '{user.username}' is now {'active' if user.is_active_user else 'disabled'}.", "ok")
    return redirect(url_for("admin.users"))


@bp.route("/audit")
@roles_required("admin", "auditor")
def audit_log():
    action = request.args.get("action", "").strip()
    query = AuditLog.query
    if action:
        query = query.filter(AuditLog.action == action)
    rows = query.order_by(AuditLog.id.desc()).limit(300).all()
    actions = [a[0] for a in db.session.query(AuditLog.action).distinct().order_by(AuditLog.action).all()]
    return render_template("audit.html", rows=rows, actions=actions, selected=action)


@bp.route("/audit/verify", methods=["POST"])
@roles_required("admin", "auditor")
def audit_verify():
    ok, total, broken = verify_chain()
    log("AUDIT_CHAIN_CHECKED", details=f"ok={ok} rows={total}")
    if ok:
        flash(f"Audit chain intact: all {total} entries verified.", "ok")
    else:
        flash(f"AUDIT CHAIN BROKEN at entry #{broken}. Log records were altered or removed.", "error")
    return redirect(url_for("admin.audit_log"))
