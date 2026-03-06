from flask import Blueprint, request, render_template, redirect, url_for, flash, session
from models import db, Application, Secret
import hvac
from config import Config
from datetime import datetime
from functools import wraps


vault_bp = Blueprint('vault', __name__)

vault_client = hvac.Client(
    url=Config.VAULT_URL,
    token=Config.VAULT_TOKEN,
    verify=Config.VAULT_CACERT if Config.VAULT_CACERT else True  # True works for HTTP
)

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


# ---------------- Helper Functions ----------------
def log_secret_action(app_id, status, admin_id=None, notes="", deleted_at=None):
    """
    Logs secret actions in the database.
    """
    timestamp = deleted_at or datetime.utcnow()
    secret_log = Secret(
        app_id=app_id,
        status=status,
        deleted_by=admin_id,
        deleted_at=timestamp if status in ['deleted', 'error'] else None,
        notes=notes
    )
    db.session.add(secret_log)
    db.session.commit()


def vault_read_secret(app_name, key_type):
    """
    Reads a secret from Vault.
    """
    path = f"{app_name}_{key_type}"
    return vault_client.secrets.kv.v2.read_secret_version(path=path)['data']['data'].get(key_type)


def vault_upload_secret(app_name, key_type, key_value):
    """
    Uploads a secret to Vault.
    """
    path = f"{app_name}_{key_type}"
    vault_client.secrets.kv.v2.create_or_update_secret(path=path, secret={key_type: key_value})


def vault_delete_secret(app_name, key_type):
    """
    Deletes a secret from Vault. Returns True if existed and deleted, False if missing.
    """
    path = f"{app_name}_{key_type}"
    try:
        vault_client.secrets.kv.v2.read_secret_version(path=path)
        vault_client.secrets.kv.v2.delete_metadata_and_all_versions(path=path)
        return True
    except hvac.exceptions.InvalidPath:
        return False




# ---------------- Route: Get Key ----------------
@vault_bp.route('/get_key', methods=['GET', 'POST'])
@admin_required
def get_key_page():

    apps = Application.query.all()
    private_key = None
    error = None
    app_name = None
    admin_id = session.get('admin_id')

    if request.method == 'POST':
        app_id = request.form.get('app_id')
        timestamp = datetime.utcnow()
        if not app_id:
            error = "Application is required."
        else:
            app_obj = Application.query.get(app_id)
            if not app_obj or app_obj.archived:
                error = "Application not found or archived."
            else:
                app_name = app_obj.app_name
                try:
                    private_key = vault_read_secret(app_obj.app_name, "private_key")
                    status = 'accessed' if private_key else 'missing'
                    if not private_key:
                        error = "Private key not found."
                    note_entry = f"Private key {status} from 'get private key page' by admin ID {admin_id} on {timestamp}"
                    log_secret_action(app_id, status=status, admin_id=admin_id, notes=note_entry)
                except hvac.exceptions.InvalidPath:
                    error = "Secret path does not exist."
                    note_entry = f"Attempted access to missing private key path from 'get private key page' by admin ID {admin_id} on {timestamp}"
                    log_secret_action(app_id, status='missing', admin_id=admin_id, notes=note_entry)
                except Exception as e:
                    error = str(e)
                    note_entry = f"Error accessing private key from 'get private key page' by admin ID {admin_id} on {timestamp}: {str(e)}"
                    log_secret_action(app_id, status='error', admin_id=admin_id, notes=note_entry)

    return render_template('get_key.html', apps=apps, private_key=private_key, error=error, app_name=app_name)


# ---------------- Route: Get Public Key ----------------
@vault_bp.route('/get_public_key', methods=['GET', 'POST'])
@admin_required
def get_public_key_page():
    apps = Application.query.all()
    public_key = None
    error = None
    app_name = None
    admin_id = session.get('admin_id')

    if request.method == 'POST':
        app_id = request.form.get('app_id')
        timestamp = datetime.utcnow()
        if not app_id:
            error = "Application is required."
        else:
            app_obj = Application.query.get(app_id)
            if not app_obj or app_obj.archived:
                error = "Application not found or archived."
            else:
                app_name = app_obj.app_name
                try:
                    public_key = vault_read_secret(app_obj.app_name, "public_key")
                    status = 'accessed' if public_key else 'missing'
                    if not public_key:
                        error = "Public key not found."
                    note_entry = f"Public key {status} from 'get public key page' by admin ID {admin_id} on {timestamp}"
                    log_secret_action(app_id, status=status, admin_id=admin_id, notes=note_entry)
                except hvac.exceptions.InvalidPath:
                    error = "Secret path does not exist."
                    note_entry = f"Invalid path access from 'get public key page' by admin ID {admin_id} on {timestamp}"
                    log_secret_action(app_id, status='missing', admin_id=admin_id, notes=note_entry)
                except Exception as e:
                    error = str(e)
                    note_entry = f"Error accessing public key from 'get public key page' by admin ID {admin_id} on {timestamp}: {str(e)}"
                    log_secret_action(app_id, status='error', admin_id=admin_id, notes=note_entry)

    return render_template('get_public_key.html', apps=apps, public_key=public_key, error=error, app_name=app_name)


# ---------------- Route: Upload Key ----------------
def handle_upload(app_id, key_type, key_value, admin_id):
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    app_obj = Application.query.get(app_id)
    if not app_obj:
        return "Selected application not found.", None

    try:
        vault_upload_secret(app_obj.app_name, key_type, key_value)

        secret_entry = Secret.query.filter_by(app_id=app_id, status='active').first()
        if secret_entry:
            secret_entry.updated_at = datetime.utcnow()
            secret_entry.updated_by = admin_id
            secret_entry.version = (secret_entry.version or 1) + 1
            note_entry = f"{key_type.capitalize()} updated on {timestamp} by Admin ID {admin_id}"
            secret_entry.notes = (secret_entry.notes or "") + ", " + note_entry
        else:
            secret_entry = Secret(
                app_id=app_id,
                created_at=datetime.utcnow(),
                uploaded_by=admin_id,
                version=1,
                status="active",
                notes=f"{key_type.capitalize()} created on {timestamp} by Admin ID {admin_id}"
            )
            db.session.add(secret_entry)

        db.session.commit()
        note_entry = f"{key_type.capitalize()} uploaded by Admin ID {admin_id} on {timestamp}"
        log_secret_action(app_id, status='accessed', admin_id=admin_id, notes=note_entry)
        return None, f"{key_type.capitalize()} for {app_obj.app_name} uploaded successfully!"
    except Exception as e:
        note_entry = f"Error uploading {key_type} by Admin ID {admin_id} on {datetime.utcnow()}: {str(e)}"
        log_secret_action(app_id, status='error', admin_id=admin_id, notes=note_entry)
        return str(e), None


@vault_bp.route('/upload_key', methods=['GET', 'POST'])
@admin_required
def upload_key_page():

    apps = Application.query.all()
    success = None
    error = None
    admin_id = session.get('admin_id')

    if request.method == 'POST':
        app_id = request.form.get('app_id')
        private_key = request.form.get('private_key')
        if not app_id or not private_key:
            error = "Application and private key are required."
        else:
            error, success = handle_upload(app_id, "private_key", private_key, admin_id)

    return render_template('upload_key.html', success=success, error=error, apps=apps)


@vault_bp.route('/upload_public_key', methods=['GET', 'POST'])
@admin_required
def upload_public_key_page():
    apps = Application.query.all()
    success = None
    error = None
    admin_id = session.get('admin_id')

    if request.method == 'POST':
        app_id = request.form.get('app_id')
        public_key = request.form.get('public_key')
        if not app_id or not public_key:
            error = "Application and public key are required."
        else:
            error, success = handle_upload(app_id, "public_key", public_key, admin_id)

    return render_template('upload_public_key.html', success=success, error=error, apps=apps)


# ---------------- Route: Delete Key ----------------
def handle_delete(app_id, key_type, admin_id):
    timestamp = datetime.utcnow()
    app_obj = Application.query.get(app_id)
    if not app_obj or app_obj.archived:
        return "Application not found or archived.", None

    try:
        existed = vault_delete_secret(app_obj.app_name, key_type)
        status = 'deleted' if existed else 'deleted_attempt'
        note_entry = f"{key_type.capitalize()} {'deleted' if existed else 'not found'} by admin ID {admin_id} on {timestamp}"
        log_secret_action(app_id, status=status, admin_id=admin_id, notes=note_entry, deleted_at=timestamp if existed else None)

        success = f"{key_type.capitalize()} for {app_obj.app_name} deleted successfully." if existed else None
        return None, success
    except Exception as e:
        note_entry = f"Error deleting {key_type} by admin ID {admin_id} on {timestamp}: {str(e)}"
        log_secret_action(app_id, status='error', admin_id=admin_id, notes=note_entry)
        return f"An error occurred while deleting the {key_type}: {str(e)}", None


@vault_bp.route('/delete_key', methods=['GET', 'POST'])
@admin_required
def delete_key_page():

    apps = Application.query.all()
    success = None
    error = None
    selected_app_name = None
    admin_id = session.get('admin_id')

    if request.method == 'POST':
        app_id = request.form.get('app_id')
        if not app_id:
            error = "Application is required."
        else:
            selected_app_name = Application.query.get(app_id).app_name if Application.query.get(app_id) else None
            error, success = handle_delete(app_id, "private_key", admin_id)

    return render_template('delete_key.html', success=success, error=error, apps=apps, selected_app_name=selected_app_name)


@vault_bp.route('/delete_public_key', methods=['GET', 'POST'])
@admin_required
def delete_public_key_page():
    apps = Application.query.all()
    success = None
    error = None
    selected_app_name = None
    admin_id = session.get('admin_id')

    if request.method == 'POST':
        app_id = request.form.get('app_id')
        if not app_id:
            error = "Application is required."
        else:
            selected_app_name = Application.query.get(app_id).app_name if Application.query.get(app_id) else None
            error, success = handle_delete(app_id, "public_key", admin_id)

    return render_template('delete_public_key.html', success=success, error=error, apps=apps, selected_app_name=selected_app_name)


# ---------------- Route: Secret Versions ----------------
@vault_bp.route('/secret_versions', methods=['GET', 'POST'])
@admin_required
def secret_versions_page():
    apps = Application.query.order_by(Application.app_name).all()
    selected_app = None
    secrets_list = []

    if request.method == 'POST':
        app_id = request.form.get('app_id')
        if not app_id:
            flash("Please select an application.", "danger")
        else:
            selected_app = Application.query.get(app_id)
            if not selected_app:
                flash("Application not found.", "danger")
            else:
                secrets_list = (
                    Secret.query
                    .filter_by(app_id=app_id)
                    .order_by(Secret.version.desc(), Secret.id.desc())
                    .all()
                )

    return render_template('secret_versions.html', apps=apps, selected_app=selected_app, secrets=secrets_list)
