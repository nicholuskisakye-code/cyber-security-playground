
from flask import Flask, render_template, request, jsonify, send_from_directory, redirect, url_for
import os, sqlite3, json, base64, subprocess, socket, hashlib, secrets
from playground.encryption import aes_encrypt, aes_decrypt, rsa_generate_keys, rsa_encrypt, rsa_decrypt
from playground.hashing import hash_password_bcrypt, verify_password_bcrypt, sha256_hash
from playground.jwt_tools import create_jwt, decode_jwt
from PIL import Image
from io import BytesIO

app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

DB = 'playground/vuln.db'

def query_db(q):
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute(q)
    rows = cur.fetchall()
    conn.close()
    return rows

@app.route('/')
def index():
    return render_template('index.html')

# Encryption endpoints
@app.route('/api/encrypt/aes', methods=['POST'])
def api_aes_encrypt():
    data = request.json or {}
    plaintext = data.get('text','').encode()
    key = data.get('key') or None
    token = aes_encrypt(plaintext, key)
    return jsonify({'token': token})

@app.route('/api/encrypt/aes/decrypt', methods=['POST'])
def api_aes_decrypt():
    data = request.json or {}
    token = data.get('token','')
    key = data.get('key') or None
    try:
        pt = aes_decrypt(token, key)
        return jsonify({'text': pt.decode()})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# RSA keys
@app.route('/api/rsa/generate', methods=['GET'])
def api_rsa_generate():
    priv, pub = rsa_generate_keys()
    return jsonify({'private_key': priv.decode(), 'public_key': pub.decode()})

@app.route('/api/rsa/encrypt', methods=['POST'])
def api_rsa_encrypt():
    data = request.json or {}
    pub = data.get('public_key','').encode()
    text = data.get('text','').encode()
    token = rsa_encrypt(pub, text)
    return jsonify({'token': token})

@app.route('/api/rsa/decrypt', methods=['POST'])
def api_rsa_decrypt():
    data = request.json or {}
    priv = data.get('private_key','').encode()
    token = data.get('token','')
    try:
        pt = rsa_decrypt(priv, token)
        return jsonify({'text': pt.decode()})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Hashing
@app.route('/api/hash/bcrypt', methods=['POST'])
def api_hash_bcrypt():
    data = request.json or {}
    pwd = data.get('password','')
    h = hash_password_bcrypt(pwd)
    return jsonify({'hash': h.decode()})

@app.route('/api/hash/verify', methods=['POST'])
def api_hash_verify():
    data = request.json or {}
    pwd = data.get('password','')
    h = data.get('hash','').encode()
    ok = verify_password_bcrypt(pwd, h)
    return jsonify({'valid': ok})

@app.route('/api/hash/sha256', methods=['POST'])
def api_sha256():
    data = request.json or {}
    t = data.get('text','')
    return jsonify({'sha256': sha256_hash(t)})

# JWT Demo
@app.route('/api/jwt/create', methods=['POST'])
def api_jwt_create():
    data = request.json or {}
    payload = data.get('payload', {'user':'nemesis'})
    token = create_jwt(payload)
    return jsonify({'token': token})

@app.route('/api/jwt/decode', methods=['POST'])
def api_jwt_decode():
    data = request.json or {}
    token = data.get('token','')
    try:
        payload = decode_jwt(token)
        return jsonify({'payload': payload})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# Vulnerable SQLi demo (LOCAL ONLY)
@app.route('/vuln/login', methods=['GET','POST'])
def vuln_login():
    if request.method == 'POST':
        username = request.form.get('username','')
        password = request.form.get('password','')
        # intentionally vulnerable query (DO NOT USE ONLINE)
        q = f"SELECT username FROM users WHERE username = '{username}' AND password = '{password}'"
        rows = query_db(q)
        if rows:
            return render_template('vuln_success.html', user=rows[0][0])
        return render_template('vuln_fail.html')
    return render_template('vuln_login.html')

# XSS demo page (reflective XSS example) -- outputs user input back directly (sandboxed)
@app.route('/vuln/xss', methods=['GET','POST'])
def vuln_xss():
    msg = ''
    if request.method == 'POST':
        msg = request.form.get('msg','')
    return render_template('vuln_xss.html', msg=msg)

# Port scanner (simple)
@app.route('/api/network/ports', methods=['POST'])
def api_ports():
    data = request.json or {}
    host = data.get('host','127.0.0.1')
    ports = data.get('ports','1-1024')
    start, end = 1, 1024
    if '-' in ports:
        s,e = ports.split('-')
        start, end = int(s), int(e)
    results = []
    for p in range(start, min(end, start+2000)+1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sckt:
                sckt.settimeout(0.3)
                r = sckt.connect_ex((host, p))
                if r == 0:
                    results.append({'port': p, 'open': True})
        except Exception:
            pass
    return jsonify({'results': results})

# Metadata extractor
@app.route('/api/forensics/metadata', methods=['POST'])
def api_metadata():
    f = request.files.get('file')
    if not f:
        return jsonify({'error': 'no file'}), 400
    img = Image.open(f.stream)
    exif = {}
    try:
        info = img._getexif() or {}
        for k,v in info.items():
            exif[str(k)] = str(v)
    except Exception:
        exif = {}
    return jsonify({'exif': exif})

# Static download of zip if present
@app.route('/download/<path:filename>')
def download_file(filename):
    return send_from_directory('/mnt/data', filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, port=5000)


# simple play pages
from flask import render_template
@app.route('/play/encryption')
def play_encryption(): return render_template('play_placeholder.html', title='Encryption Lab')
@app.route('/play/jwt')
def play_jwt(): return render_template('play_placeholder.html', title='JWT Playground')
@app.route('/play/network')
def play_network(): return render_template('play_placeholder.html', title='Network Tools')
@app.route('/play/forensics')
def play_forensics(): return render_template('play_placeholder.html', title='Forensics')


# OSINT whois endpoint
from playground.osint_tools import whois_query
@app.route('/api/osint/whois', methods=['POST'])
def api_whois():
    data = request.json or {}
    domain = data.get('domain','')
    if not domain:
        return jsonify({'error':'no domain provided'}), 400
    res = whois_query(domain)
    return jsonify({'whois': res})
