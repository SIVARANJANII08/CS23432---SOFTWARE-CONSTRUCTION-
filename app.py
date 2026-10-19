"""EvidenceTrail - application entry point."""
import os
import click
from flask import Flask, render_template
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import generate_password_hash

from config import Config
from models import db, User, utcnow
from storage import build_storage

login_manager = LoginManager()
csrf = CSRFProtect()


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)
    os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), "instance"), exist_ok=True)
    # Azure App Service sits behind a proxy; this makes IPs and https detection correct.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please sign in to continue."
    login_manager.login_message_category = "warn"

    app.storage = build_storage(app)

    from routes.auth import bp as auth_bp
    from routes.evidence import bp as evidence_bp
    from routes.admin import bp as admin_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(evidence_bp)
    app.register_blueprint(admin_bp)

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'")
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.template_filter("dt")
    def fmt_dt(value):
        return value.strftime("%d %b %Y, %H:%M UTC") if value else "-"

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("error.html", code=403, title="Access denied",
                               message="Your role does not allow this action. The attempt has been logged."), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template("error.html", code=404, title="Not found",
                               message="That page or record does not exist."), 404

    @app.errorhandler(413)
    def too_large(e):
        return render_template("error.html", code=413, title="File too large",
                               message=f"Maximum upload size is {app.config['MAX_UPLOAD_MB']} MB."), 413

    @app.cli.command("create-admin")
    @click.option("--username", prompt=True)
    @click.option("--full-name", prompt=True)
    @click.password_option()
    def create_admin(username, full_name, password):
        """Create an administrator account."""
        if User.query.filter_by(username=username).first():
            click.echo("That username already exists.")
            return
        db.session.add(User(username=username, full_name=full_name, role="admin",
                            password_hash=generate_password_hash(password)))
        db.session.commit()
        click.echo(f"Admin '{username}' created.")

    with app.app_context():
        db.create_all()
        # Optional first-run bootstrap (handy on Azure where you have no terminal).
        if app.config.get("ADMIN_PASSWORD") and User.query.count() == 0:
            db.session.add(User(username=app.config["ADMIN_USERNAME"], full_name="System Administrator",
                                role="admin", password_hash=generate_password_hash(app.config["ADMIN_PASSWORD"])))
            db.session.commit()
    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
