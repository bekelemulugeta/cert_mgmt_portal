from flask import Blueprint, request, render_template, redirect, url_for, session, jsonify, flash
from models import db, Admin, Application, APIToken, TokenHistory, TokenIPWhitelist, APILog
from datetime import datetime
import bcrypt
from sqlalchemy.orm import joinedload
from functools import wraps



admin_bp = Blueprint('admin', __name__)

#-------------------decorator------------------
def admin_required(f):
    """
    Decorator to ensure that admin is logged in.
    Redirects to login page if not.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('admin.login_page'))
        return f(*args, **kwargs)
    return decorated_function


# ---------------- Signup ----------------
@admin_bp.route('/signup', methods=['GET', 'POST'])
def signup_page():
    if request.method == 'POST':
        data = request.form
        username = data['username']
        password = data['password'].encode()
        password_hash = bcrypt.hashpw(password, bcrypt.gensalt()).decode()

        if Admin.query.filter_by(username=username).first():
            return jsonify({"error": "Username already exists"}), 400

        new_admin = Admin(username=username, password_hash=password_hash)
        db.session.add(new_admin)
        db.session.commit()
        return jsonify({"message": "Admin created successfully"})

    return render_template('signup.html')


@admin_bp.route('/logout')
def logout():
    # Clear all session data
    session.clear()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for('admin.login_page'))


# ---------------- Login ----------------
@admin_bp.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        data = request.form
        username = data['username']
        password = data['password'].encode()
        admin = Admin.query.filter_by(username=username).first()

        if admin and bcrypt.checkpw(password, admin.password_hash.encode()):
            session['admin_id'] = admin.admin_id
            session['is_admin'] = True
            return redirect(url_for('admin.dashboard'))
        return render_template('login.html', error="Invalid credentials")

    return render_template('login.html')




# ---------------- Dashboard ----------------
@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    app = Application.query.first()
    token = APIToken.query.first()
    return render_template('dashboard.html', app=app, token=token)




# ---------------- Generate Developer Token ----------------
@admin_bp.route('/generate_token', methods=['GET', 'POST'])
@admin_required
def generate_token_page():
    apps = Application.query.filter_by(archived=False).all()
    error = None
    success = None
    api_token = None

    if request.method == 'POST':
        app_name = request.form.get('app_name')
        expires_in_days = request.form.get('expires_in_days')
        allowed_ips = request.form.get('allowed_ips', '').strip()  # Comma-separated IPs

        if not app_name:
            error = "Application name is required."
        else:
            app_obj = Application.query.filter_by(app_name=app_name, archived=False).first()
            if not app_obj:
                error = f"Application '{app_name}' not found or archived."
            else:
                try:
                    from secrets import token_urlsafe
                    from datetime import datetime, timedelta

                    # Generate token
                    token_str = token_urlsafe(32)
                    created_at = datetime.utcnow()
                    expires_at = created_at + timedelta(days=int(expires_in_days)) if expires_in_days else None

                    api_token = APIToken(
                        token=token_str,
                        app_id=app_obj.app_id,
                        revoked=False,
                        expires_at=expires_at,
                        created_at=created_at,
                        admin_id=session['admin_id']
                    )
                    db.session.add(api_token)
                    db.session.commit()

                    # Register allowed IPs (if any)
                    if allowed_ips:
                        for ip in allowed_ips.split(','):
                            ip = ip.strip()
                            if ip:
                                ip_entry = TokenIPWhitelist(
                                    token_id=api_token.id,
                                    allowed_ip=ip,
                                    added_by=session['admin_id'],
                                    note="Added during token creation"
                                )
                                db.session.add(ip_entry)
                        db.session.commit()

                    success = f"Token generated successfully: {token_str}"

                    # Log in token history
                    history = TokenHistory(
                        token_id=api_token.id,
                        action="created",
                        performed_by=session['admin_id'],
                        description=f"Token created for app {app_obj.app_name}"
                    )
                    db.session.add(history)
                    db.session.commit()

                except Exception as e:
                    error = f"Token creation failed: {str(e)}"

    return render_template('generate_token.html', apps=apps, success=success, error=error, api_token=api_token)




# ---------------- Developer Tools ----------------
@admin_bp.route('/developer_tools', methods=['GET', 'POST'])
@admin_required
def developer_tools():

    apps = Application.query.all()
    selected_app = None
    tokens = []
    chosen_token = None
    error = None
    message = None

    if request.method == 'POST':
        app_id = request.form.get('app_id')
        selected_app = Application.query.get(app_id)

        if selected_app:
            tokens = APIToken.query.filter_by(app_id=app_id, revoked=False).all()

        if "selected_token" in request.form:
            selected = request.form["selected_token"]

            if selected == "other":
                chosen_token = request.form.get("manual_token")
                if not chosen_token:
                    error = "Please enter a custom token."
                else:
                    message = "Using manually entered token."
            else:
                chosen_token = selected
                message = "Using selected existing token."

    return render_template(
        'developer_tools.html',
        apps=apps,
        selected_app=selected_app,
        tokens=tokens,
        chosen_token=chosen_token,
        api_token=chosen_token,  # IMPORTANT FIX
        message=message,
        error=error
    )



# ---------------- Manage Tokens ----------------
@admin_bp.route('/manage_tokens', methods=['GET', 'POST'])
@admin_required
def manage_tokens():

    apps = Application.query.order_by(Application.app_name).all()
    selected_app = None
    tokens = []

    # Try to preserve selected_app from GET (back from history/logs)
    app_id = request.args.get('app_id') or request.form.get('app_id')

    if app_id:
        selected_app = Application.query.get(app_id)
        if selected_app:
            tokens = APIToken.query.filter_by(app_id=app_id).options(
                joinedload(APIToken.ip_whitelist),
                joinedload(APIToken.admin),
                joinedload(APIToken.revoked_by_admin)
            ).all()
        else:
            flash("Selected application not found.", "error")

    # Show message if no tokens exist
    if selected_app and not tokens:
        flash("No tokens found for the selected application.", "error")

    return render_template(
        'manage_tokens.html',
        apps=apps,
        selected_app=selected_app,
        tokens=tokens,
        datetime=datetime
    )




# ---------------- Revoke Token ----------------
@admin_bp.route('/revoke_token/<int:token_id>', methods=['POST'])
@admin_required
def revoke_token(token_id):

    api_token = APIToken.query.get(token_id)
    if api_token:
        api_token.revoked = True
        api_token.revoked_at = datetime.utcnow()
        api_token.revoked_by = session['admin_id']
        db.session.commit()

        # Log in history
        history = TokenHistory(
            token_id=api_token.id,
            action="revoked",
            performed_by=session['admin_id'],
            description="Token revoked"
        )
        db.session.add(history)
        db.session.commit()
        flash(f"Token {api_token.token} has been revoked.", "success")
    else:
        flash("Token not found.", "error")

    return redirect(url_for('admin.manage_tokens'))



# ---------------- Application Management ----------------
@admin_bp.route('/manage_applications', methods=['GET', 'POST'])
@admin_required
def manage_applications():

    apps = Application.query.order_by(Application.created_at.desc()).all()
    return render_template('manage_applications.html', apps=apps, datetime=datetime)



# ---------------- Add/Edit/Archive/Restore Application ----------------
@admin_bp.route('/add_application', methods=['GET', 'POST'])
@admin_required
def add_application():

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')

        if not name:
            flash("Application name is required.", "error")
        elif Application.query.filter_by(app_name=name).first():
            flash("Application already exists.", "error")
        else:
            app_obj = Application(
                app_name=name,
                description=description,
                created_by=session['admin_id']
            )
            db.session.add(app_obj)
            db.session.commit()
            flash("Application added successfully.", "success")
            return redirect(url_for('admin.manage_applications'))

    return render_template('add_application.html')



@admin_bp.route('/archive_application/<int:app_id>', methods=['POST'])
@admin_required
def archive_application(app_id):

    app_obj = Application.query.get(app_id)
    admin_user = Admin.query.get(session['admin_id'])
    if not app_obj:
        flash("Application not found.", "error")
    elif app_obj.archived:
        flash("Application is already archived.", "error")
    else:
        note = request.form.get('note')
        app_obj.archived = True
        app_obj.archived_at = datetime.utcnow()
        app_obj.archived_by = session['admin_id']
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        action_note = f"Archived by {admin_user.username} at {timestamp}"
        if note:
            action_note += f" --- {note}"
        app_obj.notes = (app_obj.notes + ", " if app_obj.notes else "") + action_note
        db.session.commit()
        flash(f"Application '{app_obj.app_name}' has been archived.", "success")
    return redirect(url_for('admin.manage_applications'))


@admin_bp.route('/restore_application/<int:app_id>', methods=['POST'])
@admin_required
def restore_application(app_id):

    admin_user = Admin.query.get(session['admin_id'])
    app_obj = Application.query.get(app_id)
    if not app_obj:
        flash("Application not found.", "error")
        return redirect(url_for('admin.manage_applications'))
    if not app_obj.archived:
        flash("Application is not archived.", "error")
        return redirect(url_for('admin.manage_applications'))

    note = request.form.get('note')
    app_obj.archived = False
    app_obj.archived_at = None
    app_obj.archived_by = None

    timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    action_note = f"Restored by {admin_user.username} at {timestamp}"
    if note:
        action_note += f" --- {note}"
    app_obj.notes = (app_obj.notes + ", " if app_obj.notes else "") + action_note

    db.session.commit()
    flash(f"Application '{app_obj.app_name}' has been restored.", "success")
    return redirect(url_for('admin.manage_applications'))



@admin_bp.route('/edit_application/<int:app_id>', methods=['GET', 'POST'])
@admin_required
def edit_application_page(app_id):

    app_obj = Application.query.get(app_id)
    admin_user = Admin.query.get(session['admin_id'])
    if not app_obj:
        flash("Application not found.", "error")
        return redirect(url_for('admin.manage_applications'))

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        note = request.form.get('note')

        # Validation errors must RETURN a response
        if not name:
            flash("Application name is required.", "error")
            return render_template('edit_application.html', app=app_obj)

        if Application.query.filter(Application.app_name == name,
                                    Application.app_id != app_id).first():
            flash("Another application with this name already exists.", "error")
            return render_template('edit_application.html', app=app_obj)

        # Updating logic
        app_obj.app_name = name
        app_obj.description = description
        app_obj.updated_by = session['admin_id']
        app_obj.updated_at = datetime.utcnow()

        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        action_note = f"Updated by {admin_user.username} at {timestamp}"
        if note:
            action_note += f" --- {note}"

        app_obj.notes = (app_obj.notes + ", " if app_obj.notes else "") + action_note

        db.session.commit()

        flash(f"Application '{name}' has been updated.", "success")
        return redirect(url_for('admin.manage_applications'))

    # GET method return
    return render_template('edit_application.html', app=app_obj)




# ---------------- Token History ----------------
@admin_bp.route('/token_history/<int:token_id>')
@admin_required
def token_history_page(token_id):

    token = APIToken.query.get(token_id)
    if not token:
        flash("Token not found.", "error")
        return redirect(url_for('admin.manage_tokens'))

    history_entries = TokenHistory.query.filter_by(token_id=token_id).order_by(TokenHistory.created_at.desc()).all()
    return render_template('token_history.html', token=token, history_entries=history_entries, datetime=datetime)


#--------------------------api audit logs only for valid tokens----------------------
@admin_bp.route('/api_logs/<int:token_id>')
@admin_required
def api_logs(token_id):
    token = APIToken.query.get_or_404(token_id)

    logs = APILog.query.filter_by(token_id=token_id).order_by(
        APILog.created_at.desc()
    ).all()

    return render_template(
        'api_logs.html',
        token=token,
        logs=logs
    )

#.......................all api audit logs for any token including non-existed -----------
@admin_bp.route('/all_api_logs')
@admin_required
def all_api_logs():

    logs = APILog.query.order_by(APILog.created_at.desc()).all()

    return render_template('all_api_logs.html', logs=logs)



#--------------------------api audit logs  for invalid / Suspicious /non-existed/expired token---------------
@admin_bp.route('/invalid_api_logs')
@admin_required
def invalid_api_logs():

    logs = APILog.query.filter(
        (APILog.token_id.is_(None)) | (APILog.app_id.is_(None))
    ).order_by(APILog.created_at.desc()).all()

    return render_template('invalid_api_logs.html', logs=logs)



# ---------------- Add IP to Token ----------------
@admin_bp.route('/token/<int:token_id>/add_ip', methods=['POST'])
@admin_required
def add_ip_to_token(token_id):

    token = APIToken.query.get(token_id)
    admin_user = Admin.query.get(session['admin_id'])
    if not token:
        flash("Token not found.", "error")
        return redirect(url_for('admin.manage_tokens'))

    ip_address = request.form.get('ip_address')
    if not ip_address:
        flash("IP address is required.", "error")
        return redirect(url_for('admin.manage_tokens'))

    # Check if IP already exists for this token
    existing_ip = TokenIPWhitelist.query.filter_by(token_id=token_id, allowed_ip=ip_address).first()
    if existing_ip:
        flash(f"IP {ip_address} is already in the whitelist.", "error")
    else:
        new_ip = TokenIPWhitelist(token_id=token_id, allowed_ip=ip_address, added_by= session['admin_id'])
        db.session.add(new_ip)
        db.session.commit()
        flash(f"IP {ip_address} added to whitelist.", "success")

        # Log in token history with notes
        history = TokenHistory(
            token_id=token_id,
            action="add_ip",
            performed_by=session['admin_id'],
            description=f"IP {ip_address} added to whitelist",
            notes=f"IP {ip_address} added to whitelist by {admin_user.username} at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        db.session.add(history)
        db.session.commit()

    return redirect(url_for('admin.manage_tokens', app_id=token.app_id))




# ---------------- Remove IP from Token ----------------
@admin_bp.route('/token/<int:token_id>/remove_ip', methods=['POST'])
@admin_required
def remove_ip_from_token(token_id):
    ip_id = request.form.get('ip_id')
    ip_entry = TokenIPWhitelist.query.get(ip_id)
    admin_user = Admin.query.get(session['admin_id'])
    if not ip_entry:
        flash("IP entry not found.", "error")
        return redirect(url_for('admin.manage_tokens', app_id=APIToken.query.get(token_id).app_id))

    ip_address = ip_entry.allowed_ip
    db.session.delete(ip_entry)
    db.session.commit()
    flash(f"IP {ip_address} removed from whitelist.", "success")

    # Log in token history with notes
    history = TokenHistory(
        token_id=token_id,
        action="remove_ip",
        performed_by=session['admin_id'],
        description=f"IP {ip_address} removed from whitelist",
        notes=f"IP {ip_address} removed from whitelist by {admin_user.username} at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}"
    )
    db.session.add(history)
    db.session.commit()

    return redirect(url_for('admin.manage_tokens', app_id=APIToken.query.get(token_id).app_id))
