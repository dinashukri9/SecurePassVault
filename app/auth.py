from flask import Blueprint, render_template, redirect, url_for, request, flash, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from app.models import User
from app.encryption import hash_master_password, verify_master_password
from app.activity import log_activity
from datetime import datetime, timedelta
from app import db
import hashlib

auth = Blueprint('auth', __name__)

SECURITY_QUESTIONS = [
    "What was the name of your first pet?",
    "What is your mother's maiden name?",
    "What city were you born in?",
    "What was the name of your primary school?",
    "What is your oldest sibling's middle name?",
    "What was the make of your first car?",
    "What is your favourite childhood movie?",
    "What street did you grow up on?",
    "What was your childhood nickname?",
    "What is the name of your nearest sibling?",
]

MAX_ATTEMPTS = 3
LOCKOUT_MINUTES = 5

def hash_answer(answer):
    return hashlib.sha256(answer.strip().lower().encode()).hexdigest()


@auth.route('/')
def index():
    return redirect(url_for('auth.login'))
@auth.route('/check-email')
def check_email():
    email = request.args.get('email', '')
    exists = User.query.filter_by(email=email).first() is not None
    return jsonify({'exists': exists})


# =========================
# REGISTER
# =========================
@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        sq1 = request.form.get('security_question_1')
        sa1 = request.form.get('security_answer_1')
        sq2 = request.form.get('security_question_2')
        sa2 = request.form.get('security_answer_2')
        sq3 = request.form.get('security_question_3')
        sa3 = request.form.get('security_answer_3')

        terms = request.form.get('terms')

        if not username:
            flash('Please enter a username.', 'auth_error')
            return redirect(url_for('auth.register'))

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', 'auth_error')
            return redirect(url_for('auth.register'))

        if not password or len(password) < 8:
            flash('Password must be at least 8 characters.', 'auth_error')
            return redirect(url_for('auth.register'))
        if not any(c.isdigit() for c in password):
            flash('Password must include at least one number.', 'auth_error')
            return redirect(url_for('auth.register'))
        if not any(c.isupper() for c in password):
            flash('Password must include at least one uppercase letter.', 'auth_error')
            return redirect(url_for('auth.register'))
        if not any(c.islower() for c in password):
            flash('Password must include at least one lowercase letter.', 'auth_error')
            return redirect(url_for('auth.register'))
        if not any(not c.isalnum() for c in password):
            flash('Password must include at least one symbol.', 'auth_error')
            return redirect(url_for('auth.register'))

        if password != confirm_password:
            flash('Passwords do not match.', 'auth_error')
            return redirect(url_for('auth.register'))

        if not all([sq1, sa1, sq2, sa2, sq3, sa3]):
            flash('Please answer all 3 security questions.', 'auth_error')
            return redirect(url_for('auth.register'))

        if len({sq1, sq2, sq3}) < 3:
            flash('Please select 3 different security questions.', 'auth_error')
            return redirect(url_for('auth.register'))

        if not terms:
            flash('Please agree to the terms and conditions.', 'auth_error')
            return redirect(url_for('auth.register'))

        hashed_password = hash_master_password(password)
        new_user = User(
            username=username,
            email=email,
            master_password=hashed_password,
            security_question_1=sq1, security_answer_1=hash_answer(sa1),
            security_question_2=sq2, security_answer_2=hash_answer(sa2),
            security_question_3=sq3, security_answer_3=hash_answer(sa3),
        )
        db.session.add(new_user)
        db.session.commit()

        # ── Log: account created ──
        log_activity(new_user.id, 'register', f'Account created for {email}')

        session['pending_2fa_user_id'] = new_user.id
        return redirect(url_for('two_fa_bp.setup_2fa'))

    return render_template('register.html', security_questions=SECURITY_QUESTIONS)


# =========================
# LOGIN
# =========================
@auth.route('/login', methods=['GET', 'POST'])
def login():
    timeout_msg = session.pop('timeout_msg', None)

    lockout_until = session.get('lockout_until')
    lockout_remaining = 0

    if lockout_until:
        lockout_dt = datetime.fromisoformat(lockout_until)
        if datetime.utcnow() < lockout_dt:
            lockout_remaining = int((lockout_dt - datetime.utcnow()).total_seconds())
        else:
            session.pop('lockout_until', None)
            session.pop('attempts', None)
            lockout_remaining = 0

    if request.method == 'POST':
        if lockout_remaining > 0:
            return render_template('login.html',
                                   timeout_msg=timeout_msg,
                                   lockout_remaining=lockout_remaining)

        email = request.form.get('email')
        password = request.form.get('password')

        if 'attempts' not in session:
            session['attempts'] = 0

        user = User.query.filter_by(email=email).first()

        if not user or not verify_master_password(user.master_password, password):
            session['attempts'] += 1
            remaining_attempts = MAX_ATTEMPTS - session['attempts']

            # ── Log: failed login (only if user exists — avoid leaking emails) ──
            if user:
                log_activity(user.id, 'login_failed',
                             f'Wrong password — {remaining_attempts} attempt(s) remaining',
                             status='failed')

            if session['attempts'] >= MAX_ATTEMPTS:
                lockout_dt = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
                session['lockout_until'] = lockout_dt.isoformat()
                lockout_remaining = LOCKOUT_MINUTES * 60
                session.pop('attempts', None)

                # ── Log: account locked out ──
                if user:
                    log_activity(user.id, 'login_failed',
                                 f'Account locked for {LOCKOUT_MINUTES} min after max attempts',
                                 status='failed')

                return render_template('login.html',
                                       timeout_msg=timeout_msg,
                                       lockout_remaining=lockout_remaining)
            else:
                flash(f'Invalid email or password. {remaining_attempts} attempt(s) remaining.', 'auth_error')
                return redirect(url_for('auth.login'))

        session.pop('attempts', None)
        session.pop('lockout_until', None)

        # ── Log: successful login ──
        log_activity(user.id, 'login', 'Logged in successfully')

        # Update last_login timestamp
        user.last_login = datetime.utcnow()
        db.session.commit()

        if user.two_fa_verified:
            session['pre_2fa_user_id'] = user.id
            if user.totp_enabled and user.email_2fa_enabled:
                # Both enabled — let user pick
                return redirect(url_for('two_fa_bp.choose_2fa_method'))
            elif user.totp_enabled:
                session['2fa_method_override'] = 'totp'
            elif user.email_2fa_enabled:
                session['2fa_method_override'] = 'email'
            return redirect(url_for('two_fa_bp.verify_2fa'))
        else:
            session['pending_2fa_user_id'] = user.id
            return redirect(url_for('two_fa_bp.setup_2fa'))

    return render_template('login.html',
                           timeout_msg=timeout_msg,
                           lockout_remaining=lockout_remaining)


# =========================
# LOGOUT
# =========================
@auth.route('/logout')
@login_required
def logout():
    # ── Log: logout ──
    log_activity(current_user.id, 'logout', 'Logged out')
    logout_user()
    session.clear()
    return redirect(url_for('auth.login'))