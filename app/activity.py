from flask import Blueprint, render_template, request
from flask_login import login_required, current_user
from app.models import ActivityLog
from app import db
from datetime import datetime

activity_bp = Blueprint('activity', __name__)


# ── Helper — call this from any route to log an event ────────────
def log_activity(user_id, action, detail=None, status='success'):
    """
    Log a user action to the ActivityLog table.

    Usage:
        from app.activity import log_activity
        log_activity(current_user.id, 'login', 'Logged in successfully')
        log_activity(current_user.id, 'login_failed', 'Wrong password', status='failed')
        log_activity(current_user.id, 'add_password', f'Added: {site_name}')
        log_activity(current_user.id, 'delete_password', f'Deleted: {site_name}')
        log_activity(current_user.id, 'edit_password', f'Edited: {site_name}')
        log_activity(current_user.id, 'copy_password', f'Copied: {site_name}')
        log_activity(current_user.id, 'change_2fa', 'Changed 2FA method')
        log_activity(current_user.id, 'change_timeout', 'Session timeout set to 15 min')
        log_activity(current_user.id, 'logout', 'Logged out')
    """
    try:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        # X-Forwarded-For can be comma-separated, take first
        if ip and ',' in ip:
            ip = ip.split(',')[0].strip()

        log = ActivityLog(
            user_id    = user_id,
            action     = action,
            detail     = detail,
            ip_address = ip,
            status     = status,
            timestamp  = datetime.utcnow()
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        db.session.rollback()


# ── Action labels & icons for display ────────────────────────────
ACTION_META = {
    'login':           {'label': 'Login',              'icon': '🔓', 'color': 'green'},
    'login_failed':    {'label': 'Failed Login',       'icon': '⚠️',  'color': 'red'},
    'logout':          {'label': 'Logout',             'icon': '🔒', 'color': 'blue'},
    'register':        {'label': 'Account Created',    'icon': '📝', 'color': 'green'},
    'add_password':    {'label': 'Password Added',     'icon': '➕', 'color': 'green'},
    'edit_password':   {'label': 'Password Edited',    'icon': '✏️',  'color': 'amber'},
    'delete_password': {'label': 'Password Deleted',   'icon': '🗑️',  'color': 'red'},
    'copy_password':   {'label': 'Password Copied',    'icon': '📋', 'color': 'blue'},
    'view_password':   {'label': 'Password Viewed',    'icon': '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>️',  'color': 'blue'},
    'change_2fa':      {'label': '2FA Changed',        'icon': '📱', 'color': 'amber'},
    'change_timeout':  {'label': 'Timeout Changed',    'icon': '⏱️',  'color': 'amber'},
    'password_reset':  {'label': 'Password Reset',     'icon': '🔑', 'color': 'amber'},
    'session_expired': {'label': 'Session Expired',    'icon': '⏰', 'color': 'red'},
}


@activity_bp.route('/activity-log')
@login_required
def activity_log():
    logs = (ActivityLog.query
            .filter_by(user_id=current_user.id)
            .order_by(ActivityLog.timestamp.desc())
            .limit(100)
            .all())

    # Attach display meta to each log
    for log in logs:
        meta = ACTION_META.get(log.action, {'label': log.action, 'icon': '📌', 'color': 'gray'})
        log.display_label = meta['label']
        log.display_icon  = meta['icon']
        log.display_color = meta['color']
        log.display_time  = log.timestamp.strftime('%d %b %Y, %I:%M %p')

    return render_template('activity_log.html', logs=logs)