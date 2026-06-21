from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_mail import Message
from app import db, mail
from app.models import User
from app.encryption import hash_master_password
from datetime import datetime, timedelta
import secrets
import hashlib
import pyotp

reset_bp = Blueprint('reset_bp', __name__)

MAX_TRIES = 3

def hash_answer(answer):
    return hashlib.sha256(answer.strip().lower().encode()).hexdigest()


# ─── Step 1: Choose reset method ─────────────────────────────────────
@reset_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        method = request.form.get('method')
        email  = request.form.get('email')

        user = User.query.filter_by(email=email).first()
        if not user:
            flash('No account found with that email.', 'auth_error')
            return redirect(url_for('reset_bp.forgot_password'))

        session['reset_email'] = email  # ← store early so biometric flow always has it

        # Check if account is fully locked
        if user.is_reset_locked:
            return redirect(url_for('reset_bp.account_locked'))

        # Check per-method lockout
        email_tries = session.get('reset_email_tries', 0)
        sq_tries    = session.get('reset_sq_tries', 0)

        if method == 'email_link':
            if email_tries >= MAX_TRIES:
                flash('You have exceeded the maximum attempts for email reset. Please use security questions.', 'auth_error')
                return redirect(url_for('reset_bp.forgot_password'))
            return redirect(url_for('reset_bp.send_reset_link', email=email))

        elif method == 'security_question':
            if sq_tries >= MAX_TRIES:
                flash('You have exceeded the maximum attempts for security questions. Please use email reset.', 'auth_error')
                return redirect(url_for('reset_bp.forgot_password'))
            return redirect(url_for('reset_bp.security_question_reset', email=email))

    email_tries = session.get('reset_email_tries', 0)
    sq_tries    = session.get('reset_sq_tries', 0)
    return render_template('forgot_password.html',
                           email_tries=email_tries,
                           sq_tries=sq_tries,
                           max_tries=MAX_TRIES)


# ─── Method 1: Email Link ─────────────────────────────────────────────
@reset_bp.route('/reset/send-link/<email>')
def send_reset_link(email):
    user = User.query.filter_by(email=email).first_or_404()

    session['reset_email_tries'] = session.get('reset_email_tries', 0) + 1
    session['reset_email'] = email

    token = secrets.token_urlsafe(32)
    user.reset_token        = token
    user.reset_token_expiry = datetime.utcnow() + timedelta(minutes=15)
    db.session.commit()

    reset_url = url_for('reset_bp.reset_via_link', token=token, _external=True)

    try:
        msg = Message(
            subject='SecureVault - Password Reset Link',
            recipients=[email],
            body=f"""Hi,

You requested to reset your SecureVault master password.

Click the link below (valid for 15 minutes):
{reset_url}

Attempts used: {session['reset_email_tries']}/{MAX_TRIES}

If you did not request this, ignore this email.

- SecureVault
"""
        )
        mail.send(msg)
        tries_left = MAX_TRIES - session['reset_email_tries']
        flash(f'Reset link sent! Check your email. ({tries_left} attempt(s) remaining for this method)', 'auth_success')
    except Exception:
        flash('Failed to send email. Please use another reset method.', 'auth_error')

    _check_full_lockout(user)
    return redirect(url_for('auth.login'))


@reset_bp.route('/reset/link/<token>', methods=['GET', 'POST'])
def reset_via_link(token):
    user = User.query.filter_by(reset_token=token).first()

    if not user or not user.reset_token_expiry or datetime.utcnow() > user.reset_token_expiry:
        flash('Reset link is invalid or has expired.', 'auth_error')
        return redirect(url_for('reset_bp.forgot_password'))

    if request.method == 'POST':
        new_password     = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('Passwords do not match.', 'auth_error')
            return render_template('reset_password.html', token=token)

        errors = validate_password(new_password)
        if errors:
            for e in errors:
                flash(e, 'auth_error')
            return render_template('reset_password.html', token=token)

        user.master_password    = hash_master_password(new_password)
        user.reset_token        = None
        user.reset_token_expiry = None
        user.is_reset_locked    = False
        db.session.commit()

        session.pop('reset_email_tries', None)
        session.pop('reset_sq_tries', None)

        flash('Password reset successfully! Please login.', 'auth_success')
        return redirect(url_for('auth.login'))

    return render_template('reset_password.html', token=token)


# ─── Method 2: Security Questions ────────────────────────────────────
@reset_bp.route('/reset/security-question/<email>', methods=['GET', 'POST'])
def security_question_reset(email):
    user = User.query.filter_by(email=email).first_or_404()

    if not user.security_question_1:
        flash('No security questions set for this account. Use another method.', 'auth_error')
        return redirect(url_for('reset_bp.forgot_password'))

    if request.method == 'POST':
        a1 = request.form.get('answer_1', '')
        a2 = request.form.get('answer_2', '')
        a3 = request.form.get('answer_3', '')

        wrong = []
        if hash_answer(a1) != user.security_answer_1: wrong.append('Question 1')
        if hash_answer(a2) != user.security_answer_2: wrong.append('Question 2')
        if hash_answer(a3) != user.security_answer_3: wrong.append('Question 3')

        if wrong:
            session['reset_sq_tries'] = session.get('reset_sq_tries', 0) + 1
            tries_left = MAX_TRIES - session['reset_sq_tries']

            _check_full_lockout(user)

            if session['reset_sq_tries'] >= MAX_TRIES:
                flash('Maximum attempts reached for security questions. Your account has been locked.', 'auth_error')
                return redirect(url_for('reset_bp.account_locked'))

            flash(f'Incorrect answer(s) for: {", ".join(wrong)}. {tries_left} attempt(s) remaining.', 'auth_error')
            return render_template('security_question_reset.html', user=user,
                                   tries_left=tries_left, max_tries=MAX_TRIES)

        session['reset_email'] = email
        session.pop('reset_sq_tries', None)
        return redirect(url_for('reset_bp.reset_via_security_question'))

    tries_left = MAX_TRIES - session.get('reset_sq_tries', 0)
    return render_template('security_question_reset.html', user=user,
                           tries_left=tries_left, max_tries=MAX_TRIES)


@reset_bp.route('/reset/new-password-sq', methods=['GET', 'POST'])
def reset_via_security_question():
    email = session.get('reset_email')
    if not email:
        return redirect(url_for('reset_bp.forgot_password'))

    user = User.query.filter_by(email=email).first_or_404()

    if request.method == 'POST':
        new_password     = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('Passwords do not match.', 'auth_error')
            return render_template('reset_password.html', token=None)

        errors = validate_password(new_password)
        if errors:
            for e in errors:
                flash(e, 'auth_error')
            return render_template('reset_password.html', token=None)

        user.master_password = hash_master_password(new_password)
        user.is_reset_locked = False
        db.session.commit()

        session.pop('reset_email', None)
        session.pop('reset_email_tries', None)
        session.pop('reset_sq_tries', None)

        flash('Password reset successfully! Please login.', 'auth_success')
        return redirect(url_for('auth.login'))

    return render_template('reset_password.html', token=None)


# ─── Account locked page ──────────────────────────────────────────────
@reset_bp.route('/account-locked')
def account_locked():
    return render_template('account_locked.html')


# ─── Helper: lock account if both methods exhausted ───────────────────
def _check_full_lockout(user):
    email_tries = session.get('reset_email_tries', 0)
    sq_tries    = session.get('reset_sq_tries', 0)
    if email_tries >= MAX_TRIES and sq_tries >= MAX_TRIES:
        user.is_reset_locked = True
        db.session.commit()


# ─── Password validator ───────────────────────────────────────────────
def validate_password(password):
    errors = []
    if len(password) < 8:
        errors.append('Password must be at least 8 characters.')
    if not any(c.isupper() for c in password):
        errors.append('Password must include an uppercase letter.')
    if not any(c.islower() for c in password):
        errors.append('Password must include a lowercase letter.')
    if not any(c.isdigit() for c in password):
        errors.append('Password must include a number.')
    if not any(not c.isalnum() for c in password):
        errors.append('Password must include a symbol (e.g. !@#$%).')
    return errors


# ─── Simulated Biometric Verification ────────────────────────────────
@reset_bp.route('/verify-biometric')
def verify_biometric():
    return render_template('verify_biometric.html')


# ─── Biometric → TOTP → Reset Password flow ──────────────────────────
@reset_bp.route('/verify-biometric-2fa', methods=['GET', 'POST'])
def verify_biometric_2fa():
    email = session.get('reset_email')
    if not email:
        return redirect(url_for('reset_bp.forgot_password'))

    user = User.query.filter_by(email=email).first()
    if not user:
        return redirect(url_for('reset_bp.forgot_password'))

    if not user.totp_secret:
        flash('No authenticator app linked to this account.', 'auth_error')
        return redirect(url_for('reset_bp.account_locked'))

    bio_tries = session.get('reset_bio_tries', 0)
    if bio_tries >= MAX_TRIES:
        user.is_reset_locked = True
        db.session.commit()
        return redirect(url_for('reset_bp.account_locked'))

    if request.method == 'POST':
        code = request.form.get('totp_code', '').strip()
        totp = pyotp.TOTP(user.totp_secret)

        if totp.verify(code, valid_window=1):
            session['biometric_2fa_verified'] = True
            session.pop('reset_bio_tries', None)
            return redirect(url_for('reset_bp.reset_via_security_question'))
        else:
            session['reset_bio_tries'] = bio_tries + 1
            tries_left = MAX_TRIES - session['reset_bio_tries']
            if tries_left <= 0:
                user.is_reset_locked = True
                db.session.commit()
                return redirect(url_for('reset_bp.account_locked'))
            flash(f'Invalid code. {tries_left} attempt(s) remaining.', 'auth_error')

    return render_template('verify_biometric_2fa.html')