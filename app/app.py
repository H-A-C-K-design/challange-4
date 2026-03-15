"""
The Unseen Path - CTF Challenge (Hard)
Web Exploitation + Reverse Engineering
"""
import sqlite3
import hashlib
import os
import base64
from flask import Flask, request, session, redirect, render_template, jsonify

app = Flask(__name__)
app.secret_key = base64.b64decode("dW5zZWVucGF0aHNlY3JldA==").decode()

DB_PATH = "/tmp/challenge.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY,
            key TEXT,
            value TEXT
        )
    """)
    # Regular user
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'guest', ?, 'user')",
              (hashlib.md5(b"guest123").hexdigest(),))
    # Admin user - password is intentionally weak but hidden
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'admin', ?, 'admin')",
              (hashlib.md5(b"Tr@ceAdm1n").hexdigest(),))
    # The flag is split and stored encoded
    # Part 1: base64 of "TRACECTF{count_"
    c.execute("INSERT OR IGNORE INTO secrets VALUES (1, 'fragment_a', 'VFJBQ0VDVEZ7Y291bnRf')")
    # Part 2: rot13 of "lbhe_fgrcf}"
    c.execute("INSERT OR IGNORE INTO secrets VALUES (2, 'fragment_b', 'lbhe_fgrcf}')")
    conn.commit()
    conn.close()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # VULNERABILITY: SQL Injection - unsanitized username
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashlib.md5(password.encode()).hexdigest()}'"

    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute(query)
        user = c.fetchone()
        conn.close()
    except Exception as e:
        return render_template("index.html", error=f"DB Error: {e}")

    if user:
        session["user"] = user[1]
        session["role"] = user[3]
        return redirect("/dashboard")
    return render_template("index.html", error="Invalid credentials.")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    return render_template("dashboard.html", user=session["user"], role=session["role"])

@app.route("/api/ping", methods=["POST"])
def ping():
    """VULNERABILITY: Command Injection via unsanitized host input"""
    if "user" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    host = request.json.get("host", "")

    # Intentionally vulnerable - only available after login
    # Hint: the checker binary lives at /app/checker
    result = os.popen(f"echo {host}").read()
    return jsonify({"output": result})

@app.route("/api/secrets", methods=["GET"])
def get_secrets():
    """Only accessible to admin role"""
    if session.get("role") != "admin":
        return jsonify({"error": "Forbidden"}), 403

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT key, value FROM secrets")
    rows = c.fetchall()
    conn.close()

    return jsonify({"secrets": [{"key": r[0], "value": r[1]} for r in rows]})

@app.route("/api/verify", methods=["POST"])
def verify():
    """
    Final verification endpoint.
    Accepts the assembled flag and checks it against the checker binary logic.
    The checker XORs each byte of the input with a rolling key derived from len(input).
    """
    flag = request.json.get("flag", "")

    # Mirrors the logic in /app/checker (the RE target)
    expected = "TRACECTF{count_your_steps}"
    key = len(expected)  # key = 26

    def xor_check(s, k):
        return all((ord(c) ^ (k % 256)) == v for c, v in zip(s, _encoded_flag(k)))

    def _encoded_flag(k):
        return [(ord(c) ^ (k % 256)) for c in expected]

    if flag == expected:
        return jsonify({"result": "Correct! You found the unseen path.", "verified": True})
    return jsonify({"result": "Incorrect flag.", "verified": False})

# Initialize DB on startup (works with both gunicorn and direct run)
with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
