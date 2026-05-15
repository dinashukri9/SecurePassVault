from flask import Blueprint, render_template, redirect, url_for, request, flash, session, Response
from flask_login import login_required, current_user, login_user
from flask_mail import Message
from app import db, mail
from app.models import User
from datetime import datetime, timedelta
import pyotp
import qrcode
import io
import base64
import secrets

two_fa_bp = Blueprint('two_fa_bp', __name__)


# ─── Setup: Choose 2FA method (after register) ───────────────────────
@two_fa_bp.route('/setup-2fa', methods=['GET', 'POST'])
def setup_2fa():
    # Must have pending_user_id in session (set after register)
    user_id = session.get('pending_2fa_user_id')
    if not user_id:
        return redirect(url_for('auth.login'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        method = request.form.get('method')
        if method == 'totp':
            return redirect(url_for('two_fa_bp.setup_totp'))
        elif method == 'email':
            return redirect(url_for('two_fa_bp.setup_email_2fa'))

    return render_template('setup_2fa_choose.html')


# ─── Setup TOTP (Google Authenticator) ───────────────────────────────
@two_fa_bp.route('/setup-2fa/totp', methods=['GET', 'POST'])
def setup_totp():
    user_id = session.get('pending_2fa_user_id')
    if not user_id:
        return redirect(url_for('auth.login'))

    user = User.query.get(user_id)

    # Generate secret if not already
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        db.session.commit()

    totp = pyotp.TOTP(user.totp_secret)
    otp_uri = totp.provisioning_uri(name=user.email, issuer_name='SecureVault')

    # Generate QR code as base64
    qr = qrcode.make(otp_uri)
    buf = io.BytesIO()
    qr.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        if totp.verify(code, valid_window=1):
            user.two_fa_method = 'totp'
            user.two_fa_verified = True
            db.session.commit()
            session.pop('pending_2fa_user_id', None)
            flash('2FA setup complete! Please login.', 'auth_success')
            return redirect(url_for('auth.login'))
        else:
            flash('Invalid code. Try again.', 'auth_error')

    return render_template('setup_totp.html', qr_b64=qr_b64, secret=user.totp_secret)


# ─── Setup Email 2FA ─────────────────────────────────────────────────
@two_fa_bp.route('/setup-2fa/email', methods=['GET', 'POST'])
def setup_email_2fa():
    user_id = session.get('pending_2fa_user_id')
    if not user_id:
        return redirect(url_for('auth.login'))

    user = User.query.get(user_id)

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'send':
            # Send verification code
            code = str(secrets.randbelow(900000) + 100000)
            user.two_fa_temp_code = code
            user.two_fa_code_expiry = datetime.utcnow() + timedelta(minutes=5)
            db.session.commit()

            try:
                msg = Message(
                    subject='SecureVault - 2FA Setup Code',
                    recipients=[user.email],
                    body=f"""Hi,

Your SecureVault 2FA setup code is:

{code}

Valid for 5 minutes.

- SecureVault
"""
                )
                mail.send(msg)
                flash('Code sent to your email!', 'auth_success')
            except Exception:
                flash('Failed to send email. Please try again.', 'auth_error')

            return render_template('setup_email_2fa.html', code_sent=True)

        elif action == 'verify':
            code = request.form.get('code', '').strip()

            if not user.two_fa_code_expiry or datetime.utcnow() > user.two_fa_code_expiry:
                flash('Code expired. Please request a new one.', 'auth_error')
                return render_template('setup_email_2fa.html', code_sent=False)

            if code == user.two_fa_temp_code:
                user.two_fa_method = 'email'
                user.two_fa_verified = True
                user.two_fa_temp_code = None
                user.two_fa_code_expiry = None
                db.session.commit()
                session.pop('pending_2fa_user_id', None)
                flash('2FA setup complete! Please login.', 'auth_success')
                return redirect(url_for('auth.login'))
            else:
                flash('Incorrect code.', 'auth_error')
                return render_template('setup_email_2fa.html', code_sent=True)

    return render_template('setup_email_2fa.html', code_sent=False)


# ─── Login: Verify 2FA ────────────────────────────────────────────────
@two_fa_bp.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        return redirect(url_for('auth.login'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('auth.login'))

    # Use session override if user picked a method, else fall back to user's method
    method = session.get('2fa_method_override') or user.two_fa_method

    # If email — auto-send code on GET
    if request.method == 'GET' and method == 'email':
        _send_login_otp(user)

    if request.method == 'POST':
        action = request.form.get('action', 'verify')

        if action == 'resend' and method == 'email':
            _send_login_otp(user)
            return render_template('verify_2fa.html', method=method)

        code = request.form.get('code', '').strip()

        if method == 'totp':
            totp = pyotp.TOTP(user.totp_secret)
            valid = totp.verify(code, valid_window=1)
        else:
            if not user.two_fa_code_expiry or datetime.utcnow() > user.two_fa_code_expiry:
                flash('Code expired. Please request a new one.', 'auth_error')
                return render_template('verify_2fa.html', method=method)
            valid = (code == user.two_fa_temp_code)

        if valid:
            user.two_fa_temp_code = None
            user.two_fa_code_expiry = None
            user.last_login = datetime.utcnow()
            db.session.commit()

            session.pop('pre_2fa_user_id', None)
            session.pop('2fa_method_override', None)  # ← clear override
            session['last_active'] = datetime.utcnow().isoformat()
            login_user(user)
            return redirect(url_for('vault.dashboard'))
        else:
            flash('Invalid code. Try again.', 'auth_error')

    return render_template('verify_2fa.html', method=method)


# ─── Choose 2FA method (when both enabled) ───────────────────────────
@two_fa_bp.route('/choose-2fa-method', methods=['GET', 'POST'])
def choose_2fa_method():
    user_id = session.get('pre_2fa_user_id')
    if not user_id:
        return redirect(url_for('auth.login'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        method = request.form.get('method')
        if method in ['totp', 'email']:
            session['2fa_method_override'] = method
            if method == 'email':
                _send_login_otp(user)
            return redirect(url_for('two_fa_bp.verify_2fa'))

    return render_template('choose_2fa_method.html',
                           totp_enabled=user.totp_enabled,
                           email_2fa_enabled=user.email_2fa_enabled)


def _send_login_otp(user):
    """Send OTP email for login 2FA."""
    code = str(secrets.randbelow(900000) + 100000)
    user.two_fa_temp_code = code
    user.two_fa_code_expiry = datetime.utcnow() + timedelta(minutes=5)
    db.session.commit()

    try:
        msg = Message(
            subject='SecureVault - Your Login Code',
            recipients=[user.email],
            body=f"""Hi,

Your SecureVault login verification code is:

{code}

Valid for 5 minutes. Do not share this with anyone.

- SecureVault
"""
        )
        mail.send(msg)
    except Exception:
        flash('Failed to send 2FA code. Try again.', 'auth_error')