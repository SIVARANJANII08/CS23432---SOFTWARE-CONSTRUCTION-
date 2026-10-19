"""Builds app.zip for Azure deployment (only the needed files, Linux-safe paths)."""
import os, zipfile

FILES = ["app.py", "audit.py", "config.py", "models.py", "storage.py", "requirements.txt"]
DIRS = ["routes", "templates", "static"]

with zipfile.ZipFile("app.zip", "w", zipfile.ZIP_DEFLATED) as z:
    for f in FILES:
        z.write(f, f)
    for d in DIRS:
        for root, _, names in os.walk(d):
            if "__pycache__" in root:
                continue
            for n in names:
                p = os.path.join(root, n)
                z.write(p, p.replace(os.sep, "/"))
print("app.zip created")
