import os
import sqlite3
from flask import Flask, request, redirect, url_for, render_template_string, send_file, session, abort
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# --- Config ---
app = Flask(__name__)
app.secret_key = 'your_super_secret_key'
UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted'
DB_FILE = 'users.db'
KEY = Fernet.generate_key()
cipher = Fernet(KEY)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB

# --- Setup ---
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)

# --- Database Init ---
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
                    username TEXT,
                    action TEXT,
                    filename TEXT,
                    timestamp TEXT
                )''')
    if not c.execute("SELECT * FROM users WHERE username='admin'").fetchone():
        hashed_pw = generate_password_hash('password123')
        c.execute("INSERT INTO users VALUES (?, ?)", ('admin', hashed_pw))
    conn.commit()
    conn.close()

init_db()

# --- Templates ---
LOGIN_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <title>Secure Login</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {
      background: linear-gradient(to right, #0f2027, #203a43, #2c5364);
      color: white;
      font-family: 'Segoe UI', sans-serif;
      padding-top: 100px;
    }
    .login-box {
      background-color: rgba(0,0,0,0.6);
      padding: 30px;
      border-radius: 10px;
      box-shadow: 0 0 20px #00f2ff;
      animation: fadeIn 1s ease-in;
    }
    @keyframes fadeIn {
      from {opacity: 0;}
      to {opacity: 1;}
    }
  </style>
</head>
<body>
  <div class="container text-center">
    <div class="login-box mx-auto col-md-4">
      <h2 class="mb-4">🔐 Secure Login</h2>
      <form method="post">
        <div class="mb-3">
          <input name="username" class="form-control" placeholder="Username">
        </div>
        <div class="mb-3">
          <input name="password" type="password" class="form-control" placeholder="Password">
        </div>
        <button type="submit" class="btn btn-info w-100">Login</button>
      </form>
    </div>
  </div>
</body>
</html>
"""

UPLOAD_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <title>Secure Upload</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {
      background: linear-gradient(to right, #141e30, #243b55);
      color: white;
      font-family: 'Segoe UI', sans-serif;
      padding-top: 50px;
    }
    .upload-box {
      background-color: rgba(255,255,255,0.05);
      padding: 30px;
      border-radius: 10px;
      box-shadow: 0 0 20px #00f2ff;
      animation: slideIn 1s ease-out;
    }
    @keyframes slideIn {
      from {transform: translateY(-20px); opacity: 0;}
      to {transform: translateY(0); opacity: 1;}
    }
    li {
      margin-bottom: 10px;
      transition: transform 0.3s ease;
    }
    li:hover {
      transform: scale(1.05);
    }
    a {
      color: #00f2ff;
      text-decoration: none;
    }
    a:hover {
      text-decoration: underline;
    }
  </style>
</head>
<body>
  <div class="container text-center">
    <div class="upload-box mx-auto col-md-6">
      <h2 class="mb-4">📁 Upload & Encrypt File</h2>
      <form method="post" enctype="multipart/form-data">
        <input type="file" name="file" class="form-control mb-3">
        <button type="submit" class="btn btn-success w-100">Upload</button>
      </form>
      <a href="/logout" class="btn btn-outline-light mt-3">Logout</a>
      <h3 class="mt-4">🔒 Encrypted Files:</h3>
      <ul class="list-unstyled">
        {% for f in files %}
          <li><a href="{{ url_for('download_file', filename=f) }}">{{ f }}</a></li>
        {% endfor %}
      </ul>
    </div>
  </div>
</body>
</html>
"""

# --- Routes ---
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        u = request.form['username']
        p = request.form['password']
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        user = c.execute("SELECT password FROM users WHERE username=?", (u,)).fetchone()
        conn.close()
        if user and check_password_hash(user[0], p):
            session['user'] = u
            return redirect(url_for('upload'))
    return render_template_string(LOGIN_PAGE)

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        f = request.files['file']
        filename = secure_filename(f.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        f.save(filepath)

        with open(filepath, 'rb') as file:
            data = file.read()
        encrypted_data = cipher.encrypt(data)
        encrypted_path = os.path.join(ENCRYPTED_FOLDER, filename + '.enc')
        with open(encrypted_path, 'wb') as file:
            file.write(encrypted_data)
        os.remove(filepath)

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO logs VALUES (?, ?, ?, ?)", (
            session['user'], 'upload', filename, datetime.now().isoformat()))
        conn.commit()
        conn.close()

    files = os.listdir(ENCRYPTED_FOLDER)
    return render_template_string(UPLOAD_PAGE, files=files)

@app.route('/download/<filename>')
def download_file(filename):
    if 'user' not in session:
        return redirect(url_for('login'))

    encrypted_path = os.path.join(ENCRYPTED_FOLDER, filename)
    if not os.path.exists(encrypted_path):
        abort(404)

    with open(encrypted_path, 'rb') as file:
        encrypted_data = file.read()
    decrypted_data = cipher.decrypt(encrypted_data)

    temp_path = os.path.join(UPLOAD_FOLDER, filename.replace('.enc', ''))
    with open(temp_path, 'wb') as file:
        file.write(decrypted_data)

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO logs VALUES (?, ?, ?, ?)", (
        session['user'], 'download', filename, datetime.now().isoformat()))
    conn.commit()
    conn.close()

    return send_file(temp_path, as_attachment=True)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

# --- Run ---
if __name__ == '__main__':
    app.run(debug=True)
