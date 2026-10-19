"""All settings live here. Values come from environment variables (.env file locally,
App Settings on Azure) so secrets never sit inside the source code."""
import os
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-only-secret-change-me"
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or (
        "sqlite:///" + os.path.join(BASE_DIR, "instance", "evidencetrail.db")
    )
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True, "pool_recycle": 1800}
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", "50"))
    MAX_CONTENT_LENGTH = MAX_UPLOAD_MB * 1024 * 1024
    ALLOWED_EXTENSIONS = {
        "pdf", "txt", "log", "csv", "json", "xml", "doc", "docx", "xls", "xlsx",
        "png", "jpg", "jpeg", "gif", "bmp", "mp3", "wav", "mp4", "avi", "mov",
        "zip", "pcap", "eml", "msg", "img", "dd", "e01", "bin", "db", "sqlite",
    }

    AZURE_STORAGE_CONNECTION_STRING = os.environ.get("AZURE_STORAGE_CONNECTION_STRING") or None
    AZURE_BLOB_CONTAINER = os.environ.get("AZURE_BLOB_CONTAINER", "evidence")
    LOCAL_STORAGE_DIR = os.path.join(BASE_DIR, "local_evidence")

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
    PERMANENT_SESSION_LIFETIME = 60 * 60  # 1 hour

    MAX_FAILED_LOGINS = 5
    LOCKOUT_MINUTES = 15

    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD") or None
