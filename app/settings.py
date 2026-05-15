from flask import Blueprint, render_template, redirect, url_for, request, flash, session
from flask_login import login_required, current_user
from app.encryption import verify_master_password, hash_master_password, encrypt_password, decrypt_password
from app.models import User, Password
from app import db

settings = Blueprint('settings', __name__)

ALLOWED_TIMEOUTS = [5, 10, 15, 30]


@settings.route('/settings', methods=['GET', 'POST'])
@login_required
def user_settings():

    open_section = None

    if request.method == 'POST':

        action = request.form.get('action')

        # =========================
        # SESSION TIMEOUT
        # =========================
        if action == 'timeout':

            open_section = 'timeout'
            timeout = request.form.get('session_timeout', type=int)

            if timeout not in ALLOWED_TIMEOUTS:
                flash('Invalid timeout value.', 'timeout_error')

            else:
                current_user.session_timeout = timeout
                db.session.commit()
                flash(f'Session timeout updated to {timeout} minutes.', 'timeout_success')

        # =========================
        # TOGGLE TOTP
        # =========================
        elif action == 'toggle_totp':

            if current_user.totp_enabled:

                # Only disable if email 2FA still enabled
                if current_user.email_2fa_enabled:
                    current_user.totp_enabled = False
                    db.session.commit()
                    flash('Authenticator disabled.', 'twofa_success')

                else:
                    flash('You must keep at least one 2FA method enabled.', 'twofa_error')

            else:

                # Enable TOTP
                if not current_user.totp_secret:

                    current_user.two_fa_verified = False
                    db.session.commit()

                    session['pending_2fa_user_id'] = current_user.id

                    return redirect(url_for('two_fa_bp.setup_totp'))

                else:
                    current_user.totp_enabled = True
                    db.session.commit()
                    flash('Authenticator enabled.', 'twofa_success')

        # =========================
        # TOGGLE EMAIL 2FA
        # =========================
        elif action == 'toggle_email_2fa':

            if current_user.email_2fa_enabled:

                if current_user.totp_enabled:
                    current_user.email_2fa_enabled = False
                    db.session.commit()
                    flash('Email OTP disabled.', 'twofa_success')

                else:
                    flash('You must keep at least one 2FA method enabled.', 'twofa_error')

            else:
                current_user.email_2fa_enabled = True
                db.session.commit()
                flash('Email OTP enabled.', 'twofa_success')

        # =========================
        # CHANGE EMAIL
        # =========================
        elif action == 'change_email':

            open_section = 'email'

            new_email = request.form.get('new_email', '').strip()
            confirm_email = request.form.get('confirm_email', '').strip()
            master_password = request.form.get('master_password', '')

            if not verify_master_password(current_user.master_password, master_password):
                flash('Wrong master password.', 'email_error')

            elif new_email != confirm_email:
                flash('Email addresses do not match.', 'email_error')

            elif new_email == current_user.email:
                flash('New email is the same as your current email.', 'email_error')

            else:

                existing = User.query.filter_by(email=new_email).first()

                if existing and existing.id != current_user.id:
                    flash('That email is already in use.', 'email_error')

                else:
                    current_user.email = new_email
                    db.session.commit()
                    flash('Email updated successfully.', 'email_success')

        # =========================
        # CHANGE PASSWORD
        # =========================
        elif action == 'change_password':

            open_section = 'password'

            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')

            if not verify_master_password(current_user.master_password, current_password):
                flash('Current password is incorrect.', 'password_error')

            elif new_password != confirm_password:
                flash('New passwords do not match.', 'password_error')

            else:

                errors = validate_password(new_password)

                if errors:
                    for e in errors:
                        flash(e, 'password_error')

                else:

                    passwords = Password.query.filter_by(user_id=current_user.id).all()

                    failed = 0

                    for p in passwords:

                        decrypted = decrypt_password(
                            p.encrypted_password,
                            current_password
                        )

                        if decrypted:
                            p.encrypted_password = encrypt_password(
                                decrypted,
                                new_password
                            )

                        else:
                            failed += 1

                    current_user.master_password = hash_master_password(new_password)

                    db.session.commit()

                    if failed > 0:
                        flash(
                            f'Password updated. {failed} saved password(s) could not be re-encrypted.',
                            'password_error'
                        )

                    else:
                        flash(
                            f'Master password updated. All {len(passwords)} saved passwords re-encrypted.',
                            'password_success'
                        )

        # =========================
        # REGISTER BIOMETRIC
        # =========================
        elif action == 'register_biometric':

            open_section = 'bio'

            fingers = request.form.get('fingers', '1')

            try:
                fingers = int(fingers)

                if fingers not in [1, 2]:
                    fingers = 1

            except:
                fingers = 1

            current_user.biometric_registered = True
            current_user.biometric_fingers = fingers

            db.session.commit()

            flash(
                f'Biometric registered successfully! {fingers} finger(s) linked to your account.',
                'bio_success'
            )

        # =========================
        # REMOVE BIOMETRIC
        # =========================
        elif action == 'remove_biometric':

            open_section = 'bio'

            current_user.biometric_registered = False
            current_user.biometric_fingers = 0

            db.session.commit()

            flash('Biometric removed from your account.', 'bio_success')

        return redirect(url_for('settings.user_settings', open=open_section))

    open_section = request.args.get('open', None)

    return render_template(
        'settings.html',
        current_timeout=current_user.session_timeout,
        two_fa_method=current_user.two_fa_method,
        totp_enabled=current_user.totp_enabled,
        email_2fa_enabled=current_user.email_2fa_enabled,
        last_login=current_user.last_login,
        current_email=current_user.email,
        biometric_registered=getattr(current_user, 'biometric_registered', False),
        biometric_fingers=getattr(current_user, 'biometric_fingers', 0),
        open_section=open_section
    )


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
        errors.append('Password must include a symbol.')

    return errors