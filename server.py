from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.fernet import Fernet
import bcrypt, uuid, os, json
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = os.urandom(32)  # Random secret key every restart
CORS(app, supports_credentials=True)


#  RATE LIMITER  (max 5 login attempts/minute)


limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://"
)


#  ENCRYPTION SETUP  (AES via Fernet)


ENCRYPTION_KEY = Fernet.generate_key()   # Generated fresh each run
cipher         = Fernet(ENCRYPTION_KEY)  # In production: load from env / vault

def encrypt_content(text: str) -> str:
    """Encrypt plain-text content → base64 cipher string."""
    return cipher.encrypt(text.encode()).decode()

def decrypt_content(token: str) -> str:
    """Decrypt cipher string → plain-text content."""
    return cipher.decrypt(token.encode()).decode()

#
#  SESSION CONFIG


SESSION_TIMEOUT_MINUTES = 60   # Sessions expire after 60 minutes


#  IN-MEMORY DATABASE


def hash_pw(pw: str) -> bytes:
    """Hash password with bcrypt (salted, slow by design)."""
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())

def check_pw(pw: str, hashed: bytes) -> bool:
    """Verify password against bcrypt hash."""
    return bcrypt.checkpw(pw.encode(), hashed)

USERS = {
    "admin": {
        "id":           "admin",
        "username":     "admin",
        "password":     hash_pw("admin123"),
        "role":         "admin",
        "permissions":  ["read", "write", "delete", "manage_users", "view_logs"],
        "allowed_dirs": ["/home", "/data", "/system"],
        "created_at":   datetime.now().isoformat(),
    },
    "teacher": {
        "id":           "teacher",
        "username":     "teacher",
        "password":     hash_pw("teacher123"),
        "role":         "teacher",
        "permissions":  ["read", "write", "delete", "view_logs"],
        "allowed_dirs": ["/home/teacher", "/data"],
        "created_at":   datetime.now().isoformat(),
    },
    "student": {
        "id":           "student",
        "username":     "student",
        "password":     hash_pw("student123"),
        "role":         "student",
        "permissions":  ["read", "write"],
        "allowed_dirs": ["/home/student"],
        "created_at":   datetime.now().isoformat(),
    },
}

FILES    = {}   # file_id  -> file dict  (content is encrypted)
TRASH    = {}   # file_id  -> file dict
VERSIONS = {}   # file_id  -> [version dicts]  (content is encrypted)
LOGS     = []   # list of log dicts
SESSIONS = {}   # session_token -> session info

#  HELPERS

def make_log(action: str, user: str, details: str):
    LOGS.append({
        "id":        str(uuid.uuid4()),
        "action":    action,
        "user":      user,
        "details":   details,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip":        request.remote_addr or "127.0.0.1",
    })

def safe_path(path: str) -> str:
    """
    Normalise path to prevent path-traversal attacks (../../etc).
    os.path.normpath collapses '..' components.
    """
    return os.path.normpath("/" + path.lstrip("/"))

def can_access(user_obj: dict, path: str) -> bool:
    """Check whether normalised path falls inside any allowed directory."""
    clean = safe_path(path)
    return any(clean.startswith(d) for d in user_obj["allowed_dirs"])

def get_session_user():
    """
    Retrieve the session user from the X-Session-Token header.
    Returns None if token is missing, unknown, or expired.
    """
    token = request.headers.get("X-Session-Token")
    if not token or token not in SESSIONS:
        return None

    sess = SESSIONS[token]
    login_time = datetime.fromisoformat(sess["login_time"])

    # ── Session expiry check ──────────────────
    if datetime.now() - login_time > timedelta(minutes=SESSION_TIMEOUT_MINUTES):
        del SESSIONS[token]
        make_log("SESSION_EXPIRED", sess["username"], "Session expired — auto logout")
        return None

    return sess

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_session_user()
        if not user:
            return jsonify({"success": False, "error": "Not authenticated"}), 401
        return f(user, *args, **kwargs)
    return decorated

#  SEED DATA  (content is stored encrypted)

def seed_files():
    def mk(owner, path, content):
        fid              = str(uuid.uuid4())
        encrypted        = encrypt_content(content)
        FILES[fid] = {
            "id":          fid,
            "path":        path,
            "name":        path.split("/")[-1],
            "content":     encrypted,           # ← stored encrypted
            "owner":       owner,
            "created_at":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "modified_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "size":        len(content.encode()),   # size of original
            "deleted":     False,
            "encrypted":   True,
            "inode":       abs(hash(path)) % 1_000_000,
        }
        VERSIONS[fid] = [{
            "version":   1,
            "content":   encrypted,             # ← stored encrypted
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "user":      owner,
        }]

    mk("admin",   "/home/admin/welcome.txt",   "Welcome to SecureVault!")
    mk("admin",   "/home/admin/notes.txt",      "Important system notes here.")
    mk("admin",   "/data/config.json",          '{"system":"active","version":"2.0"}')
    mk("teacher", "/home/teacher/lesson.txt",   "Lesson plan for this week.")
    mk("student", "/home/student/homework.txt", "My homework notes.")

seed_files()

#  AUTH ROUTES

@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("5 per minute")   # ← brute-force protection
def login():
    data     = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    user = USERS.get(username)

    # ── bcrypt password verification ──
    if not user or not check_pw(password, user["password"]):
        make_log("LOGIN_FAILED", username, "Invalid credentials")
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    token = str(uuid.uuid4())
    SESSIONS[token] = {
        "token":        token,
        "username":     user["username"],
        "role":         user["role"],
        "permissions":  user["permissions"],
        "allowed_dirs": user["allowed_dirs"],
        "login_time":   datetime.now().isoformat(),   # used for expiry
    }
    make_log("LOGIN_SUCCESS", username, f"Logged in as {user['role']}")
    return jsonify({
        "success": True,
        "token":   token,
        "user": {
            "username":     user["username"],
            "role":         user["role"],
            "permissions":  user["permissions"],
            "allowed_dirs": user["allowed_dirs"],
        },
    })

@app.route("/api/auth/logout", methods=["POST"])
@login_required
def logout(sess_user):
    token = request.headers.get("X-Session-Token")
    SESSIONS.pop(token, None)
    make_log("LOGOUT", sess_user["username"], "User logged out")
    return jsonify({"success": True})

#  FILE ROUTES

@app.route("/api/files", methods=["GET"])
@login_required
def list_files(sess_user):
    user_obj = USERS[sess_user["username"]]
    result   = []
    for f in FILES.values():
        if not f["deleted"] and can_access(user_obj, f["path"]):
            # Never expose encrypted content in listings
            result.append({k: v for k, v in f.items() if k != "content"})
    return jsonify({"success": True, "files": result})


@app.route("/api/files/create", methods=["POST"])
@login_required
def create_file(sess_user):
    if "write" not in sess_user["permissions"]:
        return jsonify({"success": False, "error": "Write permission denied"}), 403

    data    = request.get_json() or {}
    path    = safe_path(data.get("path", "").strip())   # sanitise immediately
    content = data.get("content", "")
    owner   = sess_user["username"]

    if not path or path == "/":
        return jsonify({"success": False, "error": "Valid path required"}), 400

    if not can_access(USERS[owner], path):
        make_log("CREATE_FAILED", owner, f"Access denied: {path}")
        return jsonify({"success": False, "error": "Access denied"}), 403

    encrypted = encrypt_content(content)
    fid       = str(uuid.uuid4())

    FILES[fid] = {
        "id":          fid,
        "path":        path,
        "name":        path.split("/")[-1],
        "content":     encrypted,
        "owner":       owner,
        "created_at":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "modified_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "size":        len(content.encode()),
        "deleted":     False,
        "encrypted":   True,
        "inode":       abs(hash(path + str(uuid.uuid4()))) % 1_000_000,
    }
    VERSIONS[fid] = [{
        "version":   1,
        "content":   encrypted,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user":      owner,
    }]

    make_log("FILE_CREATE", owner, f"File created: {path}")
    return jsonify({
        "success": True,
        "file": {k: v for k, v in FILES[fid].items() if k != "content"},
    })


@app.route("/api/files/<fid>/read", methods=["GET"])
@login_required
def read_file(sess_user, fid):
    f = FILES.get(fid)
    if not f:
        return jsonify({"success": False, "error": "File not found"}), 404
    if f["deleted"]:
        return jsonify({"success": False, "error": "File has been deleted"}), 404
    if not can_access(USERS[sess_user["username"]], f["path"]):
        make_log("READ_FAILED", sess_user["username"], f"Unauthorized read: {f['path']}")
        return jsonify({"success": False, "error": "Access denied"}), 403

    # ── Decrypt before returning to authorised user ──
    try:
        plain = decrypt_content(f["content"])
    except Exception:
        make_log("DECRYPT_ERROR", sess_user["username"], f"Decryption failed: {f['path']}")
        return jsonify({"success": False, "error": "Could not decrypt file"}), 500

    make_log("FILE_READ", sess_user["username"], f"Read: {f['path']}")
    file_data          = dict(f)
    file_data["content"] = plain   # send decrypted to authorised client
    return jsonify({"success": True, "file": file_data})


@app.route("/api/files/<fid>/write", methods=["POST"])
@login_required
def write_file(sess_user, fid):
    if "write" not in sess_user["permissions"]:
        return jsonify({"success": False, "error": "Write permission denied"}), 403

    f = FILES.get(fid)
    if not f:
        return jsonify({"success": False, "error": "File not found"}), 404
    if f["deleted"]:
        return jsonify({"success": False, "error": "File has been deleted"}), 404
    if not can_access(USERS[sess_user["username"]], f["path"]):
        make_log("WRITE_FAILED", sess_user["username"], f"Unauthorized write: {f['path']}")
        return jsonify({"success": False, "error": "Access denied"}), 403

    data        = request.get_json() or {}
    new_content = data.get("content", "")
    encrypted   = encrypt_content(new_content)

    # ── Save previous encrypted version ──────
    versions = VERSIONS.get(fid, [])
    versions.append({
        "version":   (versions[-1]["version"] if versions else 0) + 1,
        "content":   f["content"],   # already encrypted
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "user":      sess_user["username"],
    })
    VERSIONS[fid] = versions

    f["content"]     = encrypted
    f["modified_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    f["size"]        = len(new_content.encode())

    make_log("FILE_WRITE", sess_user["username"], f"Modified: {f['path']}")
    return jsonify({"success": True, "version_count": len(versions)})


@app.route("/api/files/<fid>", methods=["DELETE"])
@login_required
def delete_file(sess_user, fid):
    if "delete" not in sess_user["permissions"]:
        return jsonify({"success": False, "error": "Delete permission denied"}), 403

    f = FILES.get(fid)
    if not f:
        return jsonify({"success": False, "error": "File not found"}), 404
    if not can_access(USERS[sess_user["username"]], f["path"]):
        return jsonify({"success": False, "error": "Access denied"}), 403

    f["deleted"]    = True
    f["deleted_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    f["deleted_by"] = sess_user["username"]
    TRASH[fid]      = f

    make_log("FILE_DELETE", sess_user["username"], f"Soft-deleted: {f['path']}")
    return jsonify({"success": True, "message": "File moved to trash"})


@app.route("/api/files/<fid>/restore", methods=["POST"])
@login_required
def restore_file(sess_user, fid):
    f = TRASH.get(fid)
    if not f:
        return jsonify({"success": False, "error": "File not in trash"}), 404

    f["deleted"]     = False
    f["restored_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    f["restored_by"] = sess_user["username"]
    f.pop("deleted_at", None)
    f.pop("deleted_by", None)
    del TRASH[fid]

    make_log("FILE_RESTORE", sess_user["username"], f"Restored: {f['path']}")
    return jsonify({"success": True})


@app.route("/api/files/<fid>/permanent", methods=["DELETE"])
@login_required
def permanent_delete(sess_user, fid):
    if "delete" not in sess_user["permissions"]:
        return jsonify({"success": False, "error": "Delete permission denied"}), 403

    FILES.pop(fid, None)
    TRASH.pop(fid, None)
    VERSIONS.pop(fid, None)
    make_log("FILE_PERMANENT_DELETE", sess_user["username"], "Permanently deleted a file")
    return jsonify({"success": True})


@app.route("/api/files/<fid>/versions", methods=["GET"])
@login_required
def get_versions(sess_user, fid):
    f = FILES.get(fid)
    if not f:
        return jsonify({"success": False, "error": "File not found"}), 404
    if not can_access(USERS[sess_user["username"]], f["path"]):
        return jsonify({"success": False, "error": "Access denied"}), 403

    # Return versions with decrypted content for authorised user
    decrypted_versions = []
    for v in VERSIONS.get(fid, []):
        try:
            plain = decrypt_content(v["content"])
        except Exception:
            plain = "[decryption error]"
        decrypted_versions.append({**v, "content": plain})

    return jsonify({"success": True, "versions": decrypted_versions})

#  UTILITY ROUTES

@app.route("/api/trash", methods=["GET"])
@login_required
def list_trash(sess_user):
    items = [{k: v for k, v in f.items() if k != "content"} for f in TRASH.values()]
    return jsonify({"success": True, "trash": items})


@app.route("/api/logs", methods=["GET"])
@login_required
def get_logs(sess_user):
    if "view_logs" not in sess_user["permissions"]:
        return jsonify({"success": False, "error": "Permission denied"}), 403
    return jsonify({"success": True, "logs": list(reversed(LOGS))})


@app.route("/api/users", methods=["GET"])
@login_required
def list_users(sess_user):
    if "manage_users" not in sess_user["permissions"]:
        return jsonify({"success": False, "error": "Permission denied"}), 403
    # Never expose password hashes
    safe = [{k: v for k, v in u.items() if k != "password"} for u in USERS.values()]
    return jsonify({"success": True, "users": safe})


@app.route("/api/system/status", methods=["GET"])
@login_required
def system_status(sess_user):
    active_files = [f for f in FILES.values() if not f["deleted"]]
    return jsonify({
        "success":      True,
        "total_files":  len(active_files),
        "trash_count":  len(TRASH),
        "log_count":    len(LOGS),
        "user_count":   len(USERS),
        "total_size":   sum(f["size"] for f in active_files),
        "active_sessions": len(SESSIONS),
        "encryption":   "AES-128 (Fernet)",
        "hashing":      "bcrypt",
    })

#  ENTRY POINT

if __name__ == "__main__":
    print("=" * 52)
    print("  SecureVault Backend  —  v2.0 (Secure)")
    print("  http://localhost:5000")
    print()
    print("  Security features active:")
    print("    ✔  AES encryption  (Fernet / AES-128-CBC)")
    print("    ✔  bcrypt password hashing")
    print("    ✔  Session expiry  (60 min)")
    print("    ✔  Path-traversal protection")
    print("    ✔  Rate limiting   (5 logins/min)")
    print()
    print("  Test credentials:")
    print("    admin   / admin123")
    print("    teacher / teacher123")
    print("    student / student123")
    print("=" * 52)
    app.run(debug=True, port=5000)