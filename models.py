# models.py
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Admin(db.Model):
    __tablename__ = 'admins'
    admin_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Application(db.Model):
    __tablename__ = 'applications'
    app_id = db.Column(db.Integer, primary_key=True)
    app_name = db.Column(db.String(64), nullable=False, unique=True)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('admins.admin_id'))
    archived = db.Column(db.Boolean, default=False)
    archived_by = db.Column(db.Integer, db.ForeignKey('admins.admin_id'), nullable=True)
    archived_at = db.Column(db.DateTime, nullable=True)
    updated_by = db.Column(db.Integer, db.ForeignKey('admins.admin_id'), nullable=True)
    updated_at = db.Column(db.DateTime, nullable=True)
    notes = db.Column(db.Text)

    # Relationships
    created_by_admin = db.relationship('Admin', foreign_keys=[created_by])
    archived_by_admin = db.relationship('Admin', foreign_keys=[archived_by])
    updated_by_admin = db.relationship('Admin', foreign_keys=[updated_by])


class APIToken(db.Model):
    __tablename__ = 'api_tokens'
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(128), unique=True, nullable=False)
    app_id = db.Column(db.Integer, db.ForeignKey('applications.app_id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    revoked = db.Column(db.Boolean, default=False)
    revoked_at = db.Column(db.DateTime)
    # Who created the token
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.admin_id'))
    # Who revoked the token
    revoked_by = db.Column(db.Integer, db.ForeignKey('admins.admin_id'))

    #Provides two-way access for both Application and Admin. You can go from the related admin to see all tokens they created or revoked.
    # relationships
    admin = db.relationship("Admin", foreign_keys=[admin_id], backref="api_tokens_created")
    revoked_by_admin = db.relationship("Admin", foreign_keys=[revoked_by], backref="api_tokens_revoked")
    application = db.relationship("Application", backref="api_tokens")



class Secret(db.Model):
    __tablename__ = 'secrets'

    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.Integer, db.ForeignKey('applications.app_id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('admins.admin_id'))
    deleted_by = db.Column(db.Integer, db.ForeignKey('admins.admin_id'), nullable=True)
    deleted_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default='active')
    notes = db.Column(db.Text)
    version = db.Column(db.Integer, default=1)
    updated_by = db.Column(db.Integer, db.ForeignKey('admins.admin_id'), nullable=True)


    # relationships
    admin_uploaded = db.relationship("Admin", foreign_keys=[uploaded_by])
    admin_deleted = db.relationship("Admin", foreign_keys=[deleted_by])
    admin_updated = db.relationship("Admin", foreign_keys=[updated_by])
    application = db.relationship("Application", backref="secrets")



class TokenIPWhitelist(db.Model):
    __tablename__ = 'token_ip_whitelist'

    id = db.Column(db.Integer, primary_key=True)
    token_id = db.Column(db.Integer, db.ForeignKey('api_tokens.id'), nullable=False)
    allowed_ip = db.Column(db.String(50), nullable=False)  # fixed name and length to match DB
    note = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    added_by = db.Column(db.Integer, db.ForeignKey('admins.admin_id'))

    # relationships
    token = db.relationship("APIToken", backref="ip_whitelist")
    admin = db.relationship("Admin", backref="ip_whitelist_added")




class TokenHistory(db.Model):
    __tablename__ = 'token_history'

    id = db.Column(db.Integer, primary_key=True)
    token_id = db.Column(db.Integer, db.ForeignKey('api_tokens.id'), nullable=False)

    action = db.Column(db.String(100), nullable=False)  # rename back to match DB
    description = db.Column(db.Text)  # optional description

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    performed_by = db.Column(db.Integer, db.ForeignKey('admins.admin_id'))
    notes = db.Column(db.Text)

    # relationships
    token = db.relationship("APIToken", backref="history")
    admin = db.relationship("Admin")



class APILog(db.Model):
    __tablename__ = 'api_audit_logs'

    log_id = db.Column(db.Integer, primary_key=True)
    token_id = db.Column(db.Integer, db.ForeignKey('api_tokens.id'), nullable=True)
    app_id = db.Column(db.Integer, db.ForeignKey('applications.app_id'), nullable=True)

    action = db.Column(db.String(100), nullable=False)   # sign_jwt, sign_data, get_public_key
    endpoint = db.Column(db.String(200), nullable=False)

    payload = db.Column(db.Text)        # Request payload (JSON)
    ip_address = db.Column(db.String(64))
    status_code = db.Column(db.Integer)
    notes = db.Column(db.Text)  # notes to show success or failed

    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    token = db.relationship("APIToken")
    application = db.relationship("Application")



class SecretLog(db.Model):
    __tablename__ = 'secret_logs'

    id = db.Column(db.Integer, primary_key=True)
    secret_id = db.Column(db.Integer, db.ForeignKey('secrets.id'), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.admin_id'), nullable=True)
    action = db.Column(db.String(50), nullable=False)  # Viewed, Created, Updated, Deleted, API Access
    notes = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    secret = db.relationship("Secret", backref="logs")
    admin = db.relationship("Admin")

