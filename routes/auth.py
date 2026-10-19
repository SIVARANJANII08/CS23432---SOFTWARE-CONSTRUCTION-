from datetime import timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from models import db, User, utcnow
import audit

bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("evidence.dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        generic = "Invalid username or password."

        if user and user.locked_until and user.locked_until > utcnow():
            audit.log("LOGIN_BLOCKED", target=username, details="account locked", username=username)
            flash("Account temporarily locked after repeated failures. Try again later.", "error")
        elif user and user.is_active_user and check_password_hash(user.password_hash, password):
            user.failed_logins, user.locked_until = 0, None
            db.session.commit()
            session.clear()
            session.permanent = True
            login_user(user)
            audit.log("LOGIN_SUCCESS", target=username)
            return redirect(url_for("evidence.dashboard"))
        else:
            if user:
                user.failed_logins += 1
                if user.failed_logins >= current_app.config["MAX_FAILED_LOGINS"]:
                    user.locked_until = utcnow() + timedelta(minutes=current_app.config["LOCKOUT_MINUTES"])
                    user.failed_logins = 0
                db.session.commit()
            audit.log("LOGIN_FAILED", target=username, details="bad credentials or disabled", username=username or "unknown")
            flash(generic, "error")
    return render_template("login.html")


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    audit.log("LOGOUT", target=current_user.username)
    logout_user()
    session.clear()
    flash("You have been signed out.", "ok")
    return redirect(url_for("auth.login"))
