import io, os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import pytest
from werkzeug.security import generate_password_hash
from config import Config
from app import create_app
from models import db, User, AuditLog


class TestConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_ENGINE_OPTIONS = {}
    AZURE_STORAGE_CONNECTION_STRING = None
    ADMIN_PASSWORD = None


@pytest.fixture()
def app():
    class Cfg(TestConfig):
        LOCAL_STORAGE_DIR = tempfile.mkdtemp()
    app = create_app(Cfg)
    with app.app_context():
        for name, role in (("admin1", "admin"), ("inv1", "investigator"), ("inv2", "investigator"), ("aud1", "auditor")):
            db.session.add(User(username=name, full_name=name.title(), role=role,
                                password_hash=generate_password_hash("Passw0rd!x")))
        db.session.commit()
    yield app


def login(client, user, pw="Passw0rd!x"):
    return client.post("/login", data={"username": user, "password": pw}, follow_redirects=True)


def upload(client, content=b"secret evidence", name="note.txt"):
    return client.post("/evidence/new", data={"case_number": "C-1", "title": "Test item",
                       "file": (io.BytesIO(content), name)}, content_type="multipart/form-data", follow_redirects=True)


def test_login_required(app):
    assert app.test_client().get("/").status_code == 302


def test_bad_login_and_lockout(app):
    c = app.test_client()
    for _ in range(5):
        login(c, "inv1", "wrong")
    r = login(c, "inv1", "Passw0rd!x")
    assert b"locked" in r.data


def test_upload_hash_verify_and_tamper(app):
    c = app.test_client(); login(c, "inv1")
    r = upload(c)
    assert b"EV-" in r.data
    import hashlib
    assert hashlib.sha256(b"secret evidence").hexdigest().encode() in r.data
    assert b"PASSED" in c.post("/evidence/1/verify", follow_redirects=True).data
    folder = app.config["LOCAL_STORAGE_DIR"]
    path = os.path.join(folder, os.listdir(folder)[0])
    with open(path, "ab") as f:
        f.write(b"X")
    assert b"FAILED" in c.post("/evidence/1/verify", follow_redirects=True).data


def test_rbac_auditor_cannot_upload_or_download(app):
    c = app.test_client(); login(c, "aud1")
    assert c.get("/evidence/new").status_code == 403
    assert c.get("/admin/users").status_code == 403
    assert c.get("/audit").status_code == 200


def test_transfer_only_by_custodian(app):
    c = app.test_client(); login(c, "inv1"); upload(c)
    assert b"transferred" in c.post("/evidence/1/transfer", data={"to_user_id": 3, "reason": "to lab"}, follow_redirects=True).data.lower()
    other = app.test_client(); login(other, "inv1")  # inv1 no longer custodian
    assert other.post("/evidence/1/transfer", data={"to_user_id": 2, "reason": "sneaky"}).status_code == 403


def test_bad_extension_rejected(app):
    c = app.test_client(); login(c, "inv1")
    assert b"not allowed" in upload(c, name="evil.exe").data


def test_audit_chain_detects_tampering(app):
    c = app.test_client(); login(c, "admin1")
    c.post("/audit/verify", follow_redirects=True)
    from audit import verify_chain
    with app.app_context():
        assert verify_chain()[0]
        row = AuditLog.query.first(); row.details = "edited"; db.session.commit()
        assert not verify_chain()[0]
