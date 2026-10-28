import io
import os
import sqlite3
import uuid
from functools import wraps
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


BASE_DIR = Path(__file__).resolve().parent

load_dotenv(BASE_DIR / ".env")

DB_PATH = BASE_DIR / "instance" / "app.db"
STORAGE_DIR = BASE_DIR / "storage"

DB_PATH.parent.mkdir(exist_ok=True)
STORAGE_DIR.mkdir(exist_ok=True)


app = Flask(__name__)

secret_key = os.getenv("SECRET_KEY")
encryption_key = os.getenv("FILE_ENCRYPTION_KEY")

if not secret_key:
    raise RuntimeError("SECRET_KEY is missing from .env")

if not encryption_key:
    raise RuntimeError("FILE_ENCRYPTION_KEY is missing from .env")


app.config.update(
    SECRET_KEY=secret_key,
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

csrf = CSRFProtect(app)

try:
    fernet = Fernet(encryption_key.encode())
except Exception as exc:
    raise RuntimeError("FILE_ENCRYPTION_KEY is invalid") from exc


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row

    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)

    if db is not None:
        db.close()


def init_db():
    db = get_db()

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )

    db.commit()


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):

        if "user_id" not in session:
            flash("Please log in first.")
            return redirect(url_for("login"))

        return view(**kwargs)

    return wrapped_view


@app.route("/")
def index():

    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        error = None

        if len(username) < 3:
            error = "Username must contain at least 3 characters."

        elif len(password) < 8:
            error = "Password must contain at least 8 characters."

        elif password != confirm_password:
            error = "Passwords do not match."

        if error is None:

            db = get_db()

            existing_user = db.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,),
            ).fetchone()

            if existing_user is not None:
                error = "Username already exists."

            else:

                password_hash = generate_password_hash(password)

                db.execute(
                    """
                    INSERT INTO users (username, password_hash)
                    VALUES (?, ?)
                    """,
                    (username, password_hash),
                )

                db.commit()

                flash("Account created successfully. Please log in.")
                return redirect(url_for("login"))

        flash(error)

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()

        user = db.execute(
            """
            SELECT id, username, password_hash
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

        if user is None or not check_password_hash(
            user["password_hash"],
            password,
        ):

            flash("Invalid username or password.")
            return render_template("login.html")

        session.clear()

        session["user_id"] = user["id"]
        session["username"] = user["username"]

        flash("Login successful.")

        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():

    session.clear()

    flash("You have been logged out.")

    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():

    db = get_db()

    files = db.execute(
        """
        SELECT id, original_name, uploaded_at
        FROM files
        WHERE user_id = ?
        ORDER BY uploaded_at DESC
        """,
        (session["user_id"],),
    ).fetchall()

    return render_template(
        "dashboard.html",
        files=files,
    )


@app.route("/upload", methods=["POST"])
@login_required
def upload():

    uploaded_file = request.files.get("file")

    if not uploaded_file or uploaded_file.filename == "":

        flash("Please choose a file.")
        return redirect(url_for("dashboard"))

    original_name = secure_filename(uploaded_file.filename)

    if not original_name:

        flash("Invalid filename.")
        return redirect(url_for("dashboard"))

    file_data = uploaded_file.read()

    encrypted_data = fernet.encrypt(file_data)

    stored_name = f"{uuid.uuid4().hex}.encrypted"

    storage_path = STORAGE_DIR / stored_name

    storage_path.write_bytes(encrypted_data)

    db = get_db()

    db.execute(
        """
        INSERT INTO files (
            user_id,
            original_name,
            stored_name
        )
        VALUES (?, ?, ?)
        """,
        (
            session["user_id"],
            original_name,
            stored_name,
        ),
    )

    db.commit()

    flash("File uploaded and encrypted successfully.")

    return redirect(url_for("dashboard"))


@app.route("/download/<int:file_id>")
@login_required
def download(file_id):

    db = get_db()

    file_record = db.execute(
        """
        SELECT id, original_name, stored_name
        FROM files
        WHERE id = ?
        AND user_id = ?
        """,
        (
            file_id,
            session["user_id"],
        ),
    ).fetchone()

    if file_record is None:
        abort(404)

    storage_path = STORAGE_DIR / file_record["stored_name"]

    if not storage_path.exists():
        abort(404)

    encrypted_data = storage_path.read_bytes()

    try:
        decrypted_data = fernet.decrypt(encrypted_data)

    except InvalidToken:
        abort(500)

    return send_file(
        io.BytesIO(decrypted_data),
        as_attachment=True,
        download_name=file_record["original_name"],
    )


@app.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):

    db = get_db()

    file_record = db.execute(
        """
        SELECT id, stored_name
        FROM files
        WHERE id = ?
        AND user_id = ?
        """,
        (
            file_id,
            session["user_id"],
        ),
    ).fetchone()

    if file_record is None:
        abort(404)

    storage_path = STORAGE_DIR / file_record["stored_name"]

    if storage_path.exists():
        storage_path.unlink()

    db.execute(
        """
        DELETE FROM files
        WHERE id = ?
        AND user_id = ?
        """,
        (
            file_id,
            session["user_id"],
        ),
    )

    db.commit()

    flash("File deleted.")

    return redirect(url_for("dashboard"))


@app.errorhandler(413)
def too_large(error):

    flash("File is too large. Maximum size is 10 MB.")

    return redirect(url_for("dashboard"))


with app.app_context():
    init_db()


if __name__ == "__main__":

    cert_path = BASE_DIR / "certs" / "cert.pem"
    key_path = BASE_DIR / "certs" / "key.pem"

    if cert_path.exists() and key_path.exists():

        app.run(
            host="127.0.0.1",
            port=5000,
            debug=True,
            ssl_context=(
                str(cert_path),
                str(key_path),
            ),
        )

    else:

        print("TLS certificate not found.")
        print("Create certs/cert.pem and certs/key.pem first.")

