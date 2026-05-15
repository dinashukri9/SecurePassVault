from flask import Blueprint, render_template, redirect, url_for, request, flash, session, jsonify
from flask_login import login_required, current_user
from app.models import Password, User
from app.encryption import encrypt_password, decrypt_password, verify_master_password
from app.activity import log_activity
from app import db
from datetime import datetime, timedelta

vault = Blueprint('vault', __name__)

EXPIRY_DAYS = 90


def get_remaining_seconds():
    last_active = session.get('last_active')
    if not last_active:
        return 0
    last_active_dt = datetime.fromisoformat(last_active)
    timeout = timedelta(minutes=current_user.session_timeout)
    elapsed = datetime.utcnow() - last_active_dt
    remaining = timeout - elapsed
    return max(int(remaining.total_seconds()), 0)


def days_since(dt):
    if not dt:
        return 0
    return (datetime.utcnow() - dt).days


@vault.route('/dashboard')
@login_required
def dashboard():
    passwords = Password.query.filter_by(user_id=current_user.id).all()
    remaining_seconds = get_remaining_seconds()
    toast = request.args.get('toast', '')

    expired_count = 0
    for p in passwords:
        age = days_since(p.updated_at)
        p.days_old = age
        p.is_expired = age >= EXPIRY_DAYS
        p.is_expiring_soon = EXPIRY_DAYS - 14 <= age < EXPIRY_DAYS
        if p.is_expired:
            expired_count += 1

    return render_template('dashboard.html',
                           passwords=passwords,
                           remaining_seconds=remaining_seconds,
                           toast=toast,
                           username=current_user.username,
                           expired_count=expired_count,
                           last_login=current_user.last_login.strftime('%d %b %Y, %I:%M %p') if current_user.last_login else 'First login')


@vault.route('/add', methods=['GET', 'POST'])
@login_required
def add_password():
    if request.method == 'POST':
        site_name = request.form.get('site_name')
        username = request.form.get('username')
        password = request.form.get('password')
        url = request.form.get('url')
        notes = request.form.get('notes')
        master_password = request.form.get('master_password')

        if not site_name or not username or not password or not master_password:
            flash('Please fill in all required fields.', 'vault_error')
            return redirect(url_for('vault.add_password'))

        user = User.query.get(current_user.id)
        if not verify_master_password(user.master_password, master_password):
            log_activity(current_user.id, 'add_password',
                         f'Failed to add {site_name} — wrong master password', status='failed')
            flash('Wrong master password.', 'vault_error')
            return render_template('add_password.html', master_error='Wrong master password.')

        encrypted = encrypt_password(password, master_password)
        new_password = Password(
            user_id=current_user.id,
            site_name=site_name,
            username=username,
            encrypted_password=encrypted,
            url=url,
            notes=notes,
            updated_at=datetime.utcnow()
        )
        db.session.add(new_password)
        db.session.commit()

        log_activity(current_user.id, 'add_password', f'Added: {site_name}')
        return redirect(url_for('vault.dashboard', toast='Password saved successfully!'))

    return render_template('add_password.html')


@vault.route('/view/<int:id>', methods=['GET', 'POST'])
@login_required
def view_password(id):
    password_entry = Password.query.get_or_404(id)

    if password_entry.user_id != current_user.id:
        flash('Unauthorized access.', 'vault_error')
        return redirect(url_for('vault.dashboard'))

    decrypted = None

    if request.method == 'POST':
        master_password = request.form.get('master_password')
        decrypted = decrypt_password(password_entry.encrypted_password, master_password)

        if not decrypted:
            log_activity(current_user.id, 'view_password',
                         f'Failed to view {password_entry.site_name} — wrong master password',
                         status='failed')
            flash('Wrong master password.', 'vault_error')
        else:
            log_activity(current_user.id, 'view_password',
                         f'Viewed: {password_entry.site_name}')

    return render_template('view_password.html', entry=password_entry, decrypted=decrypted)


@vault.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete_password(id):
    password_entry = Password.query.get_or_404(id)

    if password_entry.user_id != current_user.id:
        return jsonify({'success': False, 'msg': 'Unauthorized access.'})

    master_password = request.form.get('master_password')
    user = User.query.get(current_user.id)

    if not master_password or not verify_master_password(user.master_password, master_password):
        log_activity(current_user.id, 'delete_password',
                     f'Failed to delete {password_entry.site_name} — wrong master password',
                     status='failed')
        return jsonify({'success': False, 'msg': 'Wrong master password.'})

    site_name = password_entry.site_name
    db.session.delete(password_entry)
    db.session.commit()

    log_activity(current_user.id, 'delete_password', f'Deleted: {site_name}')
    return jsonify({'success': True, 'msg': 'Password deleted successfully.'})


@vault.route('/copy/<int:id>', methods=['POST'])
@login_required
def copy_password(id):
    password_entry = Password.query.get_or_404(id)

    if password_entry.user_id != current_user.id:
        return jsonify({'success': False, 'msg': 'Unauthorized access.'})

    master_password = request.form.get('master_password')
    if not master_password:
        return jsonify({'success': False, 'msg': 'Master password required.', 'need_master': True})

    user = User.query.get(current_user.id)
    if not verify_master_password(user.master_password, master_password):
        log_activity(current_user.id, 'copy_password',
                     f'Failed to copy {password_entry.site_name} — wrong master password',
                     status='failed')
        return jsonify({'success': False, 'msg': 'Wrong master password.'})

    decrypted = decrypt_password(password_entry.encrypted_password, master_password)
    if not decrypted:
        return jsonify({'success': False, 'msg': 'Failed to decrypt password.'})

    log_activity(current_user.id, 'copy_password', f'Copied: {password_entry.site_name}')
    return jsonify({'success': True, 'password': decrypted})


@vault.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_password(id):
    password_entry = Password.query.get_or_404(id)

    if password_entry.user_id != current_user.id:
        flash('Unauthorized access.', 'vault_error')
        return redirect(url_for('vault.dashboard'))

    if request.method == 'POST':
        site_name = request.form.get('site_name')
        username = request.form.get('username')
        password = request.form.get('password')
        url = request.form.get('url', '')
        master_password = request.form.get('master_password')

        if not site_name or not username or not password or not master_password:
            flash('Please fill in all fields.', 'vault_error')
            return redirect(url_for('vault.edit_password', id=id))

        user = User.query.get(current_user.id)
        if not verify_master_password(user.master_password, master_password):
            log_activity(current_user.id, 'edit_password',
                         f'Failed to edit {password_entry.site_name} — wrong master password',
                         status='failed')
            flash('Wrong master password.', 'vault_error')
            return redirect(url_for('vault.edit_password', id=id))

        encrypted = encrypt_password(password, master_password)
        password_entry.site_name = site_name
        password_entry.username = username
        password_entry.url = url
        password_entry.encrypted_password = encrypted
        password_entry.updated_at = datetime.utcnow()
        db.session.commit()

        log_activity(current_user.id, 'edit_password', f'Edited: {site_name}')
        return redirect(url_for('vault.dashboard', toast='Password updated successfully!'))

    password_age_days = (datetime.utcnow() - password_entry.updated_at).days if password_entry.updated_at else None
    return render_template('edit_password.html', entry=password_entry, password_age_days=password_age_days)


@vault.route('/password-expiry')
@login_required
def password_expiry():
    passwords = Password.query.filter_by(user_id=current_user.id).all()

    expired  = []
    expiring = []
    healthy  = []

    for p in passwords:
        age = days_since(p.updated_at)
        p.days_old = age
        p.days_left = max(EXPIRY_DAYS - age, 0)
        p.updated_display = p.updated_at.strftime('%d %b %Y') if p.updated_at else 'Unknown'

        if age >= EXPIRY_DAYS:
            expired.append(p)
        elif age >= EXPIRY_DAYS - 14:
            expiring.append(p)
        else:
            healthy.append(p)

    return render_template('password_expiry.html',
                           expired=expired,
                           expiring=expiring,
                           healthy=healthy,
                           expiry_days=EXPIRY_DAYS)