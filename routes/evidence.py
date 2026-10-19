import hashlib
import os
import tempfile
import uuid
from flask import (Blueprint, render_template, request, redirect, url_for, flash,
                   current_app, Response, stream_with_context, abort)
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from sqlalchemy import or_
from models import db, Evidence, CustodyEvent, VerificationRecord, User, utcnow
from audit import log, roles_required

bp = Blueprint("evidence", __name__)

CAN_UPLOAD = ("admin", "investigator")
CAN_DOWNLOAD = ("admin", "investigator")


@bp.route("/")
@login_required
def dashboard():
    counts = {s: Evidence.query.filter_by(status=s).count() for s in ("Intact", "Tampered", "Unverified", "Error")}
    total = Evidence.query.count()
    mine = Evidence.query.filter_by(custodian_id=current_user.id).count()
    recent = Evidence.query.order_by(Evidence.id.desc()).limit(5).all()
    return render_template("dashboard.html", counts=counts, total=total, mine=mine, recent=recent,
                           storage_name=current_app.storage.name)


@bp.route("/evidence")
@login_required
def list_evidence():
    q = request.args.get("q", "").strip()
    query = Evidence.query
    if q:
        like = f"%{q}%"
        query = query.filter(or_(Evidence.title.like(like), Evidence.case_number.like(like),
                                 Evidence.evidence_no.like(like), Evidence.sha256.like(like)))
    items = query.order_by(Evidence.id.desc()).limit(200).all()
    return render_template("evidence_list.html", items=items, q=q)


@bp.route("/evidence/new", methods=["GET", "POST"])
@roles_required(*CAN_UPLOAD)
def new_evidence():
    if request.method == "POST":
        case_number = request.form.get("case_number", "").strip()
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        client_hash = request.form.get("client_sha256", "").strip().lower()
        upload = request.files.get("file")

        if not case_number or not title or not upload or not upload.filename:
            flash("Case number, title and a file are required.", "error")
            return render_template("evidence_new.html"), 400
        filename = secure_filename(upload.filename)
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext not in current_app.config["ALLOWED_EXTENSIONS"]:
            flash(f"File type '.{ext}' is not allowed.", "error")
            return render_template("evidence_new.html"), 400

        # Hash the bytes as they arrive (server-side SHA-256) while writing a temp copy.
        sha, size = hashlib.sha256(), 0
        tmp = tempfile.NamedTemporaryFile(delete=False)
        try:
            for chunk in iter(lambda: upload.stream.read(1024 * 1024), b""):
                sha.update(chunk)
                tmp.write(chunk)
                size += len(chunk)
            tmp.close()
            digest = sha.hexdigest()
            if size == 0:
                flash("The file is empty.", "error")
                return render_template("evidence_new.html"), 400
            if client_hash and client_hash != digest:
                log("UPLOAD_REJECTED", target=filename, details="browser hash != server hash (corrupted in transit)")
                flash("Upload rejected: the file changed in transit (browser and server hashes differ). Try again.", "error")
                return render_template("evidence_new.html"), 400

            key = f"{uuid.uuid4().hex}_{filename}"
            current_app.storage.save(tmp.name, key)
        finally:
            tmp.close()
            os.unlink(tmp.name)

        ev = Evidence(case_number=case_number, title=title, description=description,
                      original_filename=filename, content_type=upload.mimetype, size_bytes=size,
                      sha256=digest, storage_key=key, status="Unverified",
                      uploaded_by_id=current_user.id, custodian_id=current_user.id)
        db.session.add(ev)
        db.session.flush()
        ev.evidence_no = f"EV-{utcnow().year}-{ev.id:05d}"
        db.session.add(CustodyEvent(evidence_id=ev.id, action="REGISTERED", from_user_id=None,
                                    to_user_id=current_user.id, reason="Initial registration and upload"))
        db.session.commit()
        log("EVIDENCE_REGISTERED", target=ev.evidence_no, details=f"file={filename} size={size} sha256={digest}")
        flash(f"Evidence {ev.evidence_no} registered. SHA-256 recorded.", "ok")
        return redirect(url_for("evidence.detail", evidence_id=ev.id))
    return render_template("evidence_new.html")


@bp.route("/evidence/<int:evidence_id>")
@login_required
def detail(evidence_id):
    ev = db.session.get(Evidence, evidence_id) or abort(404)
    candidates = (User.query.filter(User.is_active_user.is_(True), User.id != ev.custodian_id,
                                    User.role.in_(["admin", "investigator"]))
                  .order_by(User.full_name).all())
    log("EVIDENCE_VIEWED", target=ev.evidence_no)
    can_transfer = current_user.role == "admin" or current_user.id == ev.custodian_id
    return render_template("evidence_detail.html", ev=ev, candidates=candidates, can_transfer=can_transfer,
                           can_download=current_user.role in CAN_DOWNLOAD)


@bp.route("/evidence/<int:evidence_id>/verify", methods=["POST"])
@login_required
def verify(evidence_id):
    ev = db.session.get(Evidence, evidence_id) or abort(404)
    computed, result = None, "ERROR"
    try:
        sha = hashlib.sha256()
        for chunk in current_app.storage.iter_chunks(ev.storage_key):
            sha.update(chunk)
        computed = sha.hexdigest()
        result = "PASS" if computed == ev.sha256 else "FAIL"
    except Exception as exc:  # storage unreachable or file missing
        current_app.logger.error("Verification error: %s", exc)

    ev.status = {"PASS": "Intact", "FAIL": "Tampered", "ERROR": "Error"}[result]
    ev.last_verified_at = utcnow()
    db.session.add(VerificationRecord(evidence_id=ev.id, verified_by_id=current_user.id,
                                      expected_hash=ev.sha256, computed_hash=computed, result=result))
    db.session.commit()
    log("INTEGRITY_VERIFIED", target=ev.evidence_no, details=f"result={result}")
    if result == "PASS":
        flash("Integrity check PASSED: the file matches its original SHA-256.", "ok")
    elif result == "FAIL":
        flash("Integrity check FAILED: the stored file no longer matches the original hash. Possible tampering.", "error")
    else:
        flash("Integrity check could not run: the file could not be read from storage.", "error")
    return redirect(url_for("evidence.detail", evidence_id=ev.id))


@bp.route("/evidence/<int:evidence_id>/transfer", methods=["POST"])
@login_required
def transfer(evidence_id):
    ev = db.session.get(Evidence, evidence_id) or abort(404)
    if not (current_user.role == "admin" or current_user.id == ev.custodian_id):
        log("ACCESS_DENIED", target=ev.evidence_no, details="transfer attempted by non-custodian")
        abort(403)
    reason = request.form.get("reason", "").strip()
    try:
        to_id = int(request.form.get("to_user_id", ""))
    except ValueError:
        to_id = 0
    target = db.session.get(User, to_id)
    if (not target or not target.is_active_user or target.role not in ("admin", "investigator")
            or target.id == ev.custodian_id):
        flash("Choose a valid active investigator or admin as the new custodian.", "error")
    elif len(reason) < 5:
        flash("A reason of at least 5 characters is required for every transfer.", "error")
    else:
        db.session.add(CustodyEvent(evidence_id=ev.id, action="TRANSFER", from_user_id=ev.custodian_id,
                                    to_user_id=target.id, reason=reason[:500]))
        old = ev.custodian.username
        ev.custodian_id = target.id
        db.session.commit()
        log("CUSTODY_TRANSFER", target=ev.evidence_no, details=f"{old} -> {target.username}")
        flash(f"Custody transferred to {target.full_name}.", "ok")
    return redirect(url_for("evidence.detail", evidence_id=ev.id))


@bp.route("/evidence/<int:evidence_id>/download")
@roles_required(*CAN_DOWNLOAD)
def download(evidence_id):
    ev = db.session.get(Evidence, evidence_id) or abort(404)
    log("EVIDENCE_DOWNLOADED", target=ev.evidence_no)
    resp = Response(stream_with_context(current_app.storage.iter_chunks(ev.storage_key)),
                    mimetype="application/octet-stream")
    resp.headers["Content-Disposition"] = f'attachment; filename="{ev.original_filename}"'
    return resp
