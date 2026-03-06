#api_routes
from flask import Blueprint, request, jsonify
from models import db, Application, APIToken, Secret, TokenIPWhitelist, APILog
from config import Config
import hvac
import jwt
import json
from datetime import datetime
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from binascii import unhexlify
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from Crypto.PublicKey import RSA
from functools import wraps




api_bp = Blueprint('api', __name__)

vault_client = hvac.Client(
    url=Config.VAULT_URL,
    token=Config.VAULT_TOKEN,
    verify=Config.VAULT_CACERT if Config.VAULT_CACERT else True  # True works for HTTP
)



# ---------------- Helper: Serialize any data type ----------------
def serialize_data(data):
    """
    Serialize any type of data consistently for signing and verification.
    """
    if isinstance(data, (dict, list)):
        return json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
    elif isinstance(data, (str, int, float, bool)):
        return str(data).encode()
    else:
        raise ValueError(f"Unsupported data type: {type(data)}")


# ---------------- Load public key from certificate ----------------
def load_public_key_from_cert_or_pem(pem_str):
    """
    Accepts either a certificate or a raw public key in PEM format
    Returns a PEM-encoded public key usable by both JWT and signature verification
    """
    pem_str = pem_str.strip()
    if "-----BEGIN CERTIFICATE-----" in pem_str:
        # Load certificate and extract public key
        cert = x509.load_pem_x509_certificate(pem_str.encode(), default_backend())
        public_key = cert.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    elif "-----BEGIN PUBLIC KEY-----" in pem_str:
        # Already a public key, normalize it
        key = RSA.import_key(pem_str)
        return key.export_key()  # Returns PEM bytes
    else:
        # Try to parse anyway as raw PEM
        try:
            key = RSA.import_key(pem_str)
            return key.export_key()
        except Exception:
            raise ValueError("Invalid certificate or public key format")



# ---------------- Utility: IP Whitelist ----------------
def check_ip_whitelist(token_obj):
    client_ip = request.remote_addr
    allowed_ips = [ip.allowed_ip for ip in TokenIPWhitelist.query.filter_by(token_id=token_obj.id).all()]
    if client_ip not in allowed_ips:
        return False, client_ip
    return True, client_ip


# ---------------- Helper: Verify API Token ----------------
def verify_api_token(token_str):
    if not token_str:
        return None
    api_token = APIToken.query.filter_by(token=token_str, revoked=False).first()
    if not api_token or (api_token.expires_at and api_token.expires_at < datetime.utcnow()):
        return None
    return api_token


# ---------------- Helper: Retrieve private and public key from Vault ----------------
def get_app_secret(app_obj):
    try:
        secret = vault_client.secrets.kv.v2.read_secret_version(path=f"{app_obj.app_name}_private_key")
        return secret['data']['data']
    except hvac.exceptions.InvalidPath:
        return {"error": "Secret path does not exist"}
    except Exception as e:
        return {"error": str(e)}


def get_app_public_secret(app_obj):
    try:
        secret = vault_client.secrets.kv.v2.read_secret_version(path=f"{app_obj.app_name}_public_key")
        return secret['data']['data']
    except hvac.exceptions.InvalidPath:
        return {"error": "Secret path does not exist"}
    except Exception as e:
        return {"error": str(e)}


# ---------------- Helper: Log Secret Usage ----------------
def log_secret_version_usage(secret_entry, action, performed_by):
    timestamp = datetime.utcnow()
    note_entry = f"{action} using version {secret_entry.version} at {timestamp} by Token ID {performed_by}"
    secret_entry.notes = (secret_entry.notes + ", " if secret_entry.notes else "") + note_entry
    secret_entry.last_used_at = timestamp
    db.session.commit()





# ---------------- log tokn usage ----------------
def log_api_usage(token_id, app_id, action, endpoint, payload, ip, status,notes):
    try:
        log_entry = APILog(
            token_id=token_id,
            app_id=app_id,
            action=action,
            endpoint=endpoint,
            payload=str(payload),
            ip_address=ip,
            status_code=status,
            notes=notes
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print("Audit log error:", e)

#---------------  Decorator to ensure incoming requests are JSON.------------------------
def validate_json(action_name, route_path):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Try parsing the JSON body
            try:
                request.parsed_json = request.get_json(force=True)
            except Exception as e:
                # Log invalid JSON format
                log_api_usage(
                    None, None,
                    action_name, route_path,
                    {"error": "Invalid JSON format", "raw_data": request.data.decode()},
                    request.remote_addr,
                    400,
                    f"Invalid JSON: {str(e)}"
                )
                return jsonify({"error": "Invalid JSON format"}), 400

            return func(*args, **kwargs)

        return wrapper

    return decorator


# ---------------- Developer API: Sign JWT ----------------
@api_bp.route('/sign_jwt', methods=['POST'])
@validate_json("sign_jwt", "/sign_jwt")
def sign_jwt():
    data = getattr(request, 'parsed_json', {})
    token_str = data.get('token')
    raw_payload = data.get('payload', {})

    # Validate API token
    api_token = verify_api_token(token_str)
    if not api_token:
        log_api_usage(None, None, "sign_jwt", "/sign_jwt",
                      data, request.remote_addr, 401, "Invalid, non-existed or expired token")
        return jsonify({"error": "Invalid, non-existed or expired token"}), 401

    # Fetch application and secret
    app_obj = Application.query.get(api_token.app_id)
    secret_data = get_app_secret(app_obj)
    if "error" in secret_data:
        log_api_usage(api_token.id, app_obj.app_id, "sign_jwt", "/sign_jwt",
                      data, request.remote_addr, 404, secret_data["error"])
        return jsonify(secret_data), 404

    # IP whitelist check
    allowed, client_ip = check_ip_whitelist(api_token)
    if not allowed:
        log_api_usage(api_token.id, app_obj.app_id, "sign_jwt", "/sign_jwt",
                      data, request.remote_addr, 403, f"Blocked IP: {client_ip}")
        return jsonify({"error": f"IP {client_ip} is not allowed for this token"}), 403

    # Parse payload if it is a string
    if isinstance(raw_payload, str):
        try:
            payload = json.loads(raw_payload)
        except Exception as e:
            log_api_usage(
                api_token.id, app_obj.app_id, "sign_jwt", "/sign_jwt",
                {"error": "Invalid payload JSON", "raw_payload": raw_payload},
                request.remote_addr,
                400,
                f"Payload JSON parse error: {str(e)}"
            )
            return jsonify({"error": "Invalid payload JSON"}), 400
    else:
        payload = raw_payload

    try:
        # Sign the JWT using RS256
        jwt_token = jwt.encode(payload, secret_data['private_key'], algorithm="RS256")

        # Log secret version usage
        secret_entry = Secret.query.filter_by(app_id=app_obj.app_id, status='active') \
                                   .order_by(Secret.version.desc()) \
                                   .first()
        if secret_entry:
            log_secret_version_usage(secret_entry, "JWT signed", api_token.id)

        log_api_usage(api_token.id, app_obj.app_id, "sign_jwt", "/sign_jwt",
                      data, request.remote_addr, 200, "JWT signed successfully")

        return jsonify({"data": {"jwt": jwt_token}})

    except Exception as e:
        log_api_usage(api_token.id, app_obj.app_id, "sign_jwt", "/sign_jwt",
                      {"error": str(e), "input": data}, request.remote_addr, 400, f"Signing error: {str(e)}")
        return jsonify({"error": str(e)}), 400



# ---------------- Developer API: Verify JWT ----------------
@api_bp.route('/verify_jwt', methods=['POST'])
@validate_json("verify_jwt", "/verify_jwt")
def verify_jwt():
    data = getattr(request, 'parsed_json', {})
    token_str = data.get('token')
    jwt_token = data.get('jwt')
    public_key = data.get('public_key')

    # Token validation
    api_token = verify_api_token(token_str)
    if not api_token:
        log_api_usage(None, None, "verify_jwt", "/verify_jwt",
                      data, request.remote_addr, 401, "Invalid, non-existed or expired token")
        return jsonify({"error": "Invalid ,non-existed or expired token"}), 401

    app_id = api_token.app_id

    # Validate required fields
    if not jwt_token or not public_key:
        log_api_usage(api_token.id, app_id, "verify_jwt", "/verify_jwt",
                      data, request.remote_addr, 400, "Missing jwt or public_key")
        return jsonify({"error": "jwt and public_key are required"}), 400

    # Convert certificate or public key to usable PEM format
    try:
        public_key = load_public_key_from_cert_or_pem(public_key)
    except Exception as e:
        log_api_usage(
            api_token.id, app_id, "verify_jwt", "/verify_jwt",
            {"error": str(e), "input": data}, request.remote_addr, 400,
            f"Invalid certificate or public key format:{str(e)}"
        )
        return jsonify({"error": "Invalid certificate or public key format"}), 400

    # IP whitelist check
    allowed, client_ip = check_ip_whitelist(api_token)
    if not allowed:
        log_api_usage(api_token.id, app_id, "verify_jwt", "/verify_jwt",
                      data, request.remote_addr, 403, f"Blocked IP: {client_ip}")
        return jsonify({"error": f"IP {client_ip} is not allowed for this token"}), 403

    # JWT verification
    try:

        decoded = jwt.decode(jwt_token, public_key, algorithms=["RS256"])
        log_api_usage(api_token.id, app_id, "verify_jwt", "/verify_jwt",
                      data, request.remote_addr, 200, "Verified: true")
        return jsonify({"data": {"verified": True, "payload": decoded}}), 200


    except jwt.ExpiredSignatureError:
        log_api_usage(api_token.id, app_id, "verify_jwt", "/verify_jwt",
                      data, request.remote_addr, 200, "Token expired")
        return jsonify({"data": {"verified": False, "error": "Token expired"}}), 200

    except jwt.InvalidSignatureError:
        log_api_usage(api_token.id, app_id, "verify_jwt", "/verify_jwt",
                      data, request.remote_addr, 200, "Invalid signature")
        return jsonify({"data": {"verified": False, "error": "Invalid JWT"}}), 200

    except Exception as e:
        log_api_usage(api_token.id, app_id, "verify_jwt", "/verify_jwt",
                      {"error": str(e), "input": data}, request.remote_addr, 400, f"Invalid JWT: {str(e)}")
        return jsonify({"error": f"Invalid JWT: {str(e)}"}), 400


# ---------------- Developer API: Sign Data ----------------
@api_bp.route('/sign_data', methods=['POST'])
@validate_json("sign_data", "/sign_data")
def sign_data():
    data = getattr(request, 'parsed_json', {})
    token_str = data.get('token')
    message = data.get('message')

    # Verify API token
    api_token = verify_api_token(token_str)
    if not api_token:
        log_api_usage(
            None, None,
            "sign_data", "/sign_data",
            data,
            request.remote_addr,
            401,
            "Invalid, non-existed or expired token"
        )
        return jsonify({"error": "Invalid, non-existed or expired token"}), 401

    app_obj = Application.query.get(api_token.app_id)

    # Fetch secret/private key
    secret_data = get_app_secret(app_obj)
    if "error" in secret_data:
        log_api_usage(
            api_token.id, app_obj.app_id,
            "sign_data", "/sign_data",
            data,
            request.remote_addr,
            404,
            secret_data["error"]
        )
        return jsonify(secret_data), 404

    # IP whitelist check
    allowed, client_ip = check_ip_whitelist(api_token)
    if not allowed:
        log_api_usage(
            api_token.id, app_obj.app_id,
            "sign_data", "/sign_data",
            data,
            request.remote_addr,
            403,
            f"Blocked IP: {client_ip}"
        )
        return jsonify({"error": f"IP {client_ip} is not allowed for this token"}), 403

    try:
        # Load private key
        key = RSA.import_key(secret_data['private_key'])

        # Normalize the message
        payload_bytes = serialize_data(message)

        # Hash it
        h = SHA256.new(payload_bytes)

        # Sign it
        signature = pkcs1_15.new(key).sign(h)

        # Log secret version usage
        secret_entry = Secret.query.filter_by(
            app_id=app_obj.app_id, status='active'
        ).order_by(Secret.version.desc()).first()

        if secret_entry:
            log_secret_version_usage(secret_entry, "Data signed", api_token.id)

        # Audit log
        log_api_usage(
            api_token.id, app_obj.app_id,
            "sign_data", "/sign_data",
            data,
            request.remote_addr,
            200,
            "Signature generation successful"
        )
        return jsonify({"data": {"signature": signature.hex()}}), 200


    except Exception as e:
        log_api_usage(

            api_token.id, app_obj.app_id,

            "sign_data", "/sign_data",

            {"error": str(e), "input": data},

            request.remote_addr,

            400,

            f"Signing failed: {str(e)}"

        )
        return jsonify({"error": str(e)}), 400


# ---------------- Developer API: Verify Signature ----------------
@api_bp.route('/verify_signature', methods=['POST'])
@validate_json("verify_signature", "/verify_signature")
def verify_signature():
    data = getattr(request, 'parsed_json', {})
    token_str = data.get('token')
    message = data.get('message')
    signature = data.get('signature')
    public_key = data.get('public_key')

    # Validate API token
    api_token = verify_api_token(token_str)
    if not api_token:
        log_api_usage(
            None, None,
            "verify_signature", "/verify_signature",
            data,
            request.remote_addr,
            401,
            "Invalid,non-existed  or expired token"
        )
        return jsonify({"error": "Invalid, non-existed or expired token"}), 401

    app_id = api_token.app_id

    # Validate required fields
    if message is None or not signature or not public_key:
        log_api_usage(
            api_token.id, app_id,
            "verify_signature", "/verify_signature",
            data,
            request.remote_addr,
            400,
            "Missing message, signature, or public_key"
        )
        return jsonify({"error": "Message, signature, and public_key are required"}), 400
    # Convert certificate or public key to usable PEM format
    try:
        public_key = load_public_key_from_cert_or_pem(public_key)
    except Exception as e:
        log_api_usage(
            api_token.id, app_id, "verify_signature", "/verify_signature",
            {"error": str(e), "input": data}, request.remote_addr, 400,
            f"Invalid certificate or public key format:{str(e)}"
        )
        return jsonify({"error": "Invalid certificate or public key format"}), 400

    # IP whitelist enforcement
    allowed, client_ip = check_ip_whitelist(api_token)
    if not allowed:
        log_api_usage(
            api_token.id, app_id,
            "verify_signature", "/verify_signature",
            data,
            request.remote_addr,
            403,
            f"Blocked IP: {client_ip}"
        )
        return jsonify({"error": f"IP {client_ip} is not allowed for this token"}), 403

    try:

        # Load public key
        key = RSA.import_key(public_key)

        # Normalize/serialize message
        payload_bytes = serialize_data(message)

        # Compute digest
        h = SHA256.new(payload_bytes)

        # Verify signature
        pkcs1_15.new(key).verify(h, unhexlify(signature))

        log_api_usage(
            api_token.id, app_id,
            "verify_signature", "/verify_signature",
            data,
            request.remote_addr,
            200,
            "Signature verification successful"
        )

        return jsonify({"data": {"verified": True}}), 200

    except (ValueError, TypeError) as e:
        log_api_usage(
            api_token.id, app_id,
            "verify_signature", "/verify_signature",
            {"error": str(e), "input": data},
            request.remote_addr,
            200,
            f"Signature verification failed: {str(e)}"
        )
        return jsonify({"data": {"verified": False, "error": str(e)}}), 200




# ---------------- Developer API: Get Public Key ----------------
@api_bp.route('/get_public_key', methods=['POST'])
def get_public_key():
    data = request.json
    token_str = data.get('token')

    # Validate token
    api_token = verify_api_token(token_str)
    if not api_token:
        log_api_usage(None, None, "get_public_key", "/get_public_key",
                      data, request.remote_addr, 401, "Invalid, non-existed  or expired token")
        return jsonify({"error": "Invalid, non-existed or expired token"}), 401

    # Fetch app & public key
    app_obj = Application.query.get(api_token.app_id)
    secret_data = get_app_public_secret(app_obj)

    if "error" in secret_data:
        log_api_usage(api_token.id, app_obj.app_id, "get_public_key", "/get_public_key",
                      data, request.remote_addr, 404, secret_data["error"])
        return jsonify(secret_data), 404

    # IP whitelist check
    allowed, client_ip = check_ip_whitelist(api_token)
    if not allowed:
        log_api_usage(api_token.id, app_obj.app_id, "get_public_key", "/get_public_key",
                      data, request.remote_addr, 403, f"Blocked IP: {client_ip}")
        return jsonify({"error": f"IP {client_ip} is not allowed for this token"}), 403

    # SUCCESS
    log_api_usage(api_token.id, app_obj.app_id, "get_public_key", "/get_public_key",
                  data, request.remote_addr, 200, "Success")

    return jsonify({
        "data": {
            "public_key": secret_data.get("public_key")
        }
    }), 200


