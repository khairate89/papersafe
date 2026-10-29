import os
import secrets
import sqlite3
import uuid
from pathlib import Path
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, send_file, abort, g, current_app
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = Path(os.environ.get("PAPERSAFE_DATA_DIR", BASE_DIR / "instance")).resolve()
UPLOAD_DIR = INSTANCE_DIR / "uploads"
DB_PATH = INSTANCE_DIR / "app.sqlite3"
ALLOWED_EXTENSIONS = {".pdf"}
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_MULTIPART_OVERHEAD_BYTES = 64 * 1024

INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def resolve_secret_key(environment, configured_secret, secret_file):
    configured_secret = (configured_secret or "").strip()
    if configured_secret:
        return configured_secret
    if environment != "development":
        raise RuntimeError("PDF_APP_SECRET must be set outside development mode.")

    secret_file = Path(secret_file)
    secret_file.parent.mkdir(parents=True, exist_ok=True)
    try:
        with secret_file.open("x", encoding="utf-8") as secret_stream:
            secret_stream.write(secrets.token_urlsafe(48))
    except FileExistsError:
        pass
    secret = secret_file.read_text(encoding="utf-8").strip()
    if not secret:
        raise RuntimeError("The local development secret file is empty; remove it and restart.")
    return secret


APP_ENV = os.environ.get("APP_ENV", "development").strip().lower()
SECRET_KEY = resolve_secret_key(
    APP_ENV,
    os.environ.get("PDF_APP_SECRET"),
    INSTANCE_DIR / ".flask_secret",
)

app = Flask(__name__, instance_path=str(INSTANCE_DIR))
app.config.update(
    SECRET_KEY=SECRET_KEY,
    APP_ENV=APP_ENV,
    DATABASE=str(DB_PATH),
    UPLOAD_FOLDER=str(UPLOAD_DIR),
    MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES + MAX_MULTIPART_OVERHEAD_BYTES,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=APP_ENV != "development",
)
CSRFProtect(app)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(database_path=None):
    database_path = database_path or app.config["DATABASE"]
    Path(database_path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(database_path)
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            session_version INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            stored_name TEXT NOT NULL UNIQUE,
            original_name TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS document_shares (
            document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
            recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            shared_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (document_id, recipient_id)
        );
        CREATE INDEX IF NOT EXISTS idx_document_shares_recipient
            ON document_shares(recipient_id, document_id);
        CREATE TRIGGER IF NOT EXISTS prevent_document_self_share
        BEFORE INSERT ON document_shares
        WHEN (SELECT owner_id FROM documents WHERE id = NEW.document_id) = NEW.recipient_id
        BEGIN
            SELECT RAISE(ABORT, 'document owners cannot share with themselves');
        END;
    """)
    user_columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
    if "session_version" not in user_columns:
        db.execute(
            "ALTER TABLE users ADD COLUMN "
            "session_version INTEGER NOT NULL DEFAULT 0"
        )
    db.commit()
    db.close()


@app.before_request
def load_user():
    g.user = None
    user_id = session.get("user_id")
    if user_id is not None:
        session_version = session.get("session_version")
        if type(user_id) is not int or type(session_version) is not int:
            session.clear()
            return
        user = get_db().execute(
            "SELECT id, username, session_version FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if user is not None and user["session_version"] == session_version:
            g.user = user
        else:
            session.clear()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            flash("Please log in to continue.", "info")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def index():
    if g.user:
        return redirect(url_for("documents"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3 or len(username) > 40:
            flash("Username must be between 3 and 40 characters.", "error")
        elif len(password) < 12:
            flash("Use a password with at least 12 characters.", "error")
        else:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password))
                )
                db.commit()
                flash("Account created. You can now log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is already in use.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            """SELECT id, username, password_hash, session_version
               FROM users WHERE username = ?""",
            (username,)
        ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["session_version"] = user["session_version"]
            session.permanent = True
            flash("Logged in successfully.", "success")
            return redirect(url_for("documents"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    db = get_db()
    try:
        cursor = db.execute(
            "UPDATE users SET session_version = session_version + 1 WHERE id = ?",
            (g.user["id"],),
        )
        if cursor.rowcount != 1:
            raise sqlite3.DatabaseError("Could not revoke the active user session")
        db.commit()
    except sqlite3.Error:
        db.rollback()
        current_app.logger.exception("Could not revoke session during logout")
        return render_template(
            "error.html",
            message="Logout could not be completed. Please try again.",
        ), 500
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


@app.route("/documents")
@login_required
def documents():
    query = request.args.get("q", "").strip()[:100]
    sql = """SELECT d.id, d.owner_id, d.title, d.original_name, d.size_bytes,
                    d.uploaded_at, owner.username AS owner_username,
                    CASE WHEN d.owner_id = ? THEN 1 ELSE 0 END AS is_owner
             FROM documents AS d
             JOIN users AS owner ON owner.id = d.owner_id
             LEFT JOIN document_shares AS s ON s.document_id = d.id
             WHERE (d.owner_id = ? OR s.recipient_id = ?)"""
    params = [g.user["id"], g.user["id"], g.user["id"]]
    if query:
        # Safe: search text is bound as a value, not concatenated into SQL syntax.
        sql += " AND d.title LIKE ?"
        params.append(f"%{query}%")
    sql += " ORDER BY d.uploaded_at DESC, d.id DESC"
    rows = get_db().execute(sql, params).fetchall()

    shares_by_document = {}
    shares = get_db().execute(
        """SELECT s.document_id, recipient.id AS recipient_id, recipient.username
           FROM document_shares AS s
           JOIN documents AS d ON d.id = s.document_id
           JOIN users AS recipient ON recipient.id = s.recipient_id
           WHERE d.owner_id = ?
           ORDER BY recipient.username COLLATE NOCASE""",
        (g.user["id"],)
    ).fetchall()
    for share in shares:
        shares_by_document.setdefault(share["document_id"], []).append(share)
    return render_template(
        "documents.html", documents=rows, query=query,
        shares_by_document=shares_by_document,
    )


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    if request.method == "POST":
        file = request.files.get("pdf")
        title = request.form.get("title", "").strip()[:120]
        if not file or not file.filename:
            flash("Choose a PDF file.", "error")
            return redirect(url_for("upload"))
        original = secure_filename(file.filename)
        if Path(original).suffix.lower() not in ALLOWED_EXTENSIONS:
            flash("Only .pdf files are accepted.", "error")
            return redirect(url_for("upload"))
        data = file.read(MAX_UPLOAD_BYTES + 1)
        if len(data) > MAX_UPLOAD_BYTES:
            flash("File exceeds the 10 MB limit.", "error")
            return redirect(url_for("upload"))
        # Lightweight format sanity check, not a complete malware or PDF safety scan.
        if not data.startswith(b"%PDF-"):
            flash("The file does not look like a PDF.", "error")
            return redirect(url_for("upload"))
        if not title:
            title = Path(original).stem[:120] or "Untitled PDF"

        stored_name = f"{uuid.uuid4().hex}.pdf"
        destination = Path(current_app.config["UPLOAD_FOLDER"]) / stored_name
        destination.write_bytes(data)
        try:
            get_db().execute(
                """INSERT INTO documents
                   (owner_id, title, stored_name, original_name, size_bytes)
                   VALUES (?, ?, ?, ?, ?)""",
                (g.user["id"], title, stored_name, original, len(data))
            )
            get_db().commit()
        except Exception:
            destination.unlink(missing_ok=True)
            raise
        flash("PDF uploaded.", "success")
        return redirect(url_for("documents"))
    return render_template("upload.html")


def get_owned_document(document_id):
    row = get_db().execute(
        """SELECT id, owner_id, title, stored_name, original_name, size_bytes, uploaded_at
           FROM documents WHERE id = ? AND owner_id = ?""",
        (document_id, g.user["id"])
    ).fetchone()
    if row is None:
        # Same response for missing and not-owned documents reduces information leakage.
        abort(404)
    return row


def get_accessible_document(document_id):
    row = get_db().execute(
        """SELECT d.id, d.owner_id, d.title, d.stored_name, d.original_name,
                  d.size_bytes, d.uploaded_at
           FROM documents AS d
           LEFT JOIN document_shares AS s
             ON s.document_id = d.id AND s.recipient_id = ?
           WHERE d.id = ? AND (d.owner_id = ? OR s.recipient_id = ?)""",
        (g.user["id"], document_id, g.user["id"], g.user["id"])
    ).fetchone()
    if row is None:
        abort(404)
    return row


@app.route("/documents/<int:document_id>/shares", methods=["POST"])
@login_required
def manage_document_shares(document_id):
    # Ownership is checked on the server for both sharing and revocation.
    get_owned_document(document_id)
    db = get_db()
    action = request.form.get("action", "")

    if action == "share":
        username = request.form.get("username", "").strip()
        recipient = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if recipient is None:
            flash("No account with that username was found.", "error")
        elif recipient["id"] == g.user["id"]:
            flash("A document is already available to its owner.", "info")
        else:
            try:
                db.execute(
                    "INSERT INTO document_shares (document_id, recipient_id) VALUES (?, ?)",
                    (document_id, recipient["id"]),
                )
                db.commit()
                flash(f"Document shared with {username}.", "success")
            except sqlite3.IntegrityError:
                db.rollback()
                flash("That document is already shared with this account.", "info")
    elif action == "revoke":
        try:
            recipient_id = int(request.form.get("recipient_id", ""))
        except ValueError:
            recipient_id = -1
        cursor = db.execute(
            "DELETE FROM document_shares WHERE document_id = ? AND recipient_id = ?",
            (document_id, recipient_id),
        )
        db.commit()
        if cursor.rowcount:
            flash("Document sharing was revoked.", "success")
        else:
            flash("No matching share was found.", "info")
    else:
        abort(400)
    return redirect(url_for("documents"))


@app.route("/documents/<int:document_id>/download")
@login_required
def download(document_id):
    doc = get_accessible_document(document_id)
    path = Path(current_app.config["UPLOAD_FOLDER"]) / doc["stored_name"]
    if not path.is_file():
        abort(404)
    return send_file(
        path, as_attachment=True, download_name=doc["original_name"],
        mimetype="application/pdf"
    )


@app.route("/documents/<int:document_id>/delete", methods=["POST"])
@login_required
def delete_document(document_id):
    doc = get_owned_document(document_id)
    get_db().execute(
        "DELETE FROM documents WHERE id = ? AND owner_id = ?",
        (document_id, g.user["id"])
    )
    get_db().commit()
    (Path(current_app.config["UPLOAD_FOLDER"]) / doc["stored_name"]).unlink(missing_ok=True)
    flash("Document deleted.", "success")
    return redirect(url_for("documents"))


DEMO_ACCOUNTS = {
    "alice": "PaperSafe-Alice-2026!",
    "bob": "PaperSafe-Bob-2026!",
}
DEMO_TITLE = "Welcome sample PDF"
DEMO_PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"


def seed_demo_data():
    """Create local-only synthetic demo accounts and a shared benign PDF once."""
    db = sqlite3.connect(app.config["DATABASE"])
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    db.execute("BEGIN IMMEDIATE")
    try:
        for username, password in DEMO_ACCOUNTS.items():
            db.execute(
                "INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)",
                (username, generate_password_hash(password)),
            )
        alice = db.execute("SELECT id FROM users WHERE username = ?", ("alice",)).fetchone()
        bob = db.execute("SELECT id FROM users WHERE username = ?", ("bob",)).fetchone()
        document = db.execute(
            "SELECT id, stored_name FROM documents WHERE owner_id = ? AND title = ?",
            (alice["id"], DEMO_TITLE),
        ).fetchone()
        upload_folder = Path(app.config["UPLOAD_FOLDER"])
        upload_folder.mkdir(parents=True, exist_ok=True)
        if document is None:
            stored_name = f"{uuid.uuid4().hex}.pdf"
            destination = upload_folder / stored_name
            destination.write_bytes(DEMO_PDF)
            try:
                cursor = db.execute(
                    """INSERT INTO documents
                       (owner_id, title, stored_name, original_name, size_bytes)
                       VALUES (?, ?, ?, ?, ?)""",
                    (alice["id"], DEMO_TITLE, stored_name, "welcome.pdf", len(DEMO_PDF)),
                )
                document_id = cursor.lastrowid
            except Exception:
                destination.unlink(missing_ok=True)
                raise
        else:
            document_id = document["id"]
            destination = upload_folder / document["stored_name"]
            if not destination.exists():
                destination.write_bytes(DEMO_PDF)
        db.execute(
            "INSERT OR IGNORE INTO document_shares (document_id, recipient_id) VALUES (?, ?)",
            (document_id, bob["id"]),
        )
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@app.errorhandler(413)
def too_large(_error):
    return render_template("error.html", message="Upload is too large (10 MB maximum)."), 413


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", message="The requested resource was not found."), 404


@app.cli.command("init-db")
def init_db_command():
    init_db()
    print("Database initialized.")


@app.cli.command("seed-demo")
def seed_demo_command():
    """Seed repeatable local coursework accounts and a harmless shared PDF."""
    init_db()
    seed_demo_data()
    print("Synthetic demo data is ready for local coursework use.")


if __name__ == "__main__":
    init_db()
    if os.environ.get("PAPERSAFE_SEED_DEMO") == "1":
        seed_demo_data()
    # Local development only. Do not use Flask's development server in production.
    app.run(
        debug=False,
        host=os.environ.get("PAPERSAFE_HOST", "127.0.0.1"),
        port=int(os.environ.get("PAPERSAFE_PORT", "5000")),
    )
