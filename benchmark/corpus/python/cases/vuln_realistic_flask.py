# Realistic multi-vulnerability fixture modeled on a typical vulnerable Flask
# app's shape (receiver-object method calls, f-string SQL, mixed real/safe
# routes) rather than one-sink-per-file synthetic snippets — the same lesson
# Sprint 23/24 learned from urllib.request.urlopen and context.Response.Write:
# a fixture that only tests the easy shape hides exactly the gap that matters.

import hashlib
import pickle
import subprocess
import requests
import xml.etree.ElementTree as ET
from Crypto.Cipher import DES
from flask import Flask, request, redirect, render_template_string, send_file

app = Flask(__name__)


def login():
    # ZS-PY-004: cursor.execute() with a tainted, f-string-built query
    username = request.form['username']
    query = f"SELECT * FROM user WHERE username = '{username}'"
    cursor.execute(query)


def load_session(data):
    # ZS-PY-002: pickle.loads() on attacker-controlled data
    return pickle.loads(data)


def run_diagnostic():
    # ZS-PY-012: subprocess.call() with a tainted, shell-interpreted command
    cmd = request.args.get('cmd')
    subprocess.call(cmd, shell=True)


def hash_password(password):
    # ZS-PY-007: MD5 is not safe for password hashing
    return hashlib.md5(password.encode()).hexdigest()


def fetch_avatar():
    # ZS-PY-025: SSRF — url traces back to a query parameter
    url = request.args.get('url')
    return requests.get(url)


def render_page():
    # ZS-PY-027: SSTI — the template itself, not just a render variable, is tainted
    template = request.args.get('template')
    return render_template_string(template)


def render_page_safe():
    # Safe: fixed template, only the render variable is tainted — must NOT
    # match ZS-PY-027 (argument_count: 1 requires exactly one argument).
    name = request.args.get('name')
    return render_template_string("<h1>Hello {{ name }}!</h1>", name=name)


def go_to():
    # ZS-PY-028: open redirect — destination traces back to a query parameter
    target = request.args.get('next')
    return redirect(target)


def encrypt_legacy(data):
    # ZS-PY-029: DES is a broken cipher
    key = b'weakkey1'
    return DES.new(key, DES.MODE_ECB).encrypt(data)


def safe_lookup(username):
    # Safe: parameterized query via ORM, not string-formatted — must NOT
    # match ZS-PY-004.
    return User.query.filter_by(username=username).first()


def safe_diagnostic(action):
    # Safe: allowlisted, no shell string built from user input — must NOT
    # match ZS-PY-012 (the argument passed is a fixed literal, never tainted).
    allowed = ['status', 'info']
    if action in allowed:
        subprocess.call(['echo', action], shell=False)


def run_report():
    # ZS-PY-031: subprocess.check_output() with a tainted, shell-interpreted command
    cmd = request.args.get('cmd')
    return subprocess.check_output(cmd, shell=True)


def parse_upload():
    # ZS-PY-032: XXE — the XML document itself is tainted
    xml_data = request.form['xml']
    return ET.fromstring(xml_data)


def run_plugin():
    # ZS-PY-033: exec() of attacker-supplied code
    plugin_code = request.form['code']
    exec(plugin_code)


def download_report():
    # ZS-PY-034: send_file() with a tainted, unvalidated path
    filename = request.args.get('filename')
    return send_file(filename)


def download_report_safe():
    # Safe: fixed, hardcoded filename — must NOT match ZS-PY-034
    # (tainted_argument requires the argument to trace back to a source).
    return send_file('static/report_template.pdf')
