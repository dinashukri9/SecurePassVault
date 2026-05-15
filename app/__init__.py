from flask import Flask, session, redirect, url_for, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user, logout_user
from flask_mail import Mail
from datetime import datetime, timedelta

db = SQLAlchemy()
login_manager = LoginManager()
mail = Mail()

def create_app():
    app = Flask(__name__)

    @app.after_request
    def set_security_headers(response):
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    app.config.from_object('app.config.Config')

    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    login_manager.login_view = 'auth.login'

    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # ─── Session timeout check ────────────────────────────────────────
    @app.before_request
    def check_session_timeout():
        if current_user.is_authenticated:
            last_active = session.get('last_active')
            if last_active:
                last_active_dt = datetime.fromisoformat(last_active)
                timeout_minutes = current_user.session_timeout if hasattr(current_user, 'session_timeout') else 10
                timeout = timedelta(minutes=timeout_minutes)
                if datetime.utcnow() - last_active_dt > timeout:
                    msg = f'Session expired after {timeout_minutes} minutes of inactivity.'
                    logout_user()
                    session.clear()
                    session['timeout_msg'] = msg
                    return redirect(url_for('auth.login'))
            session['last_active'] = datetime.utcnow().isoformat()

    # ─── No-cache headers for all responses ──────────────────────────
    # Prevents browser from showing cached pages after logout
    @app.after_request
    def add_no_cache_headers(response):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    # ─────────────────────────────────────────────────────────────────

    from app.auth import auth
    from app.vault import vault
    from app.settings import settings
    from app.reset_password import reset_bp
    from app.two_fa import two_fa_bp
    from app.activity import activity_bp

    app.register_blueprint(auth)
    app.register_blueprint(vault)
    app.register_blueprint(settings)
    app.register_blueprint(reset_bp)
    app.register_blueprint(two_fa_bp)
    app.register_blueprint(activity_bp)

    return app