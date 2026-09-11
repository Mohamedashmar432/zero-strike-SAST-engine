# Negative fixture for the path-traversal rule family (ZS-PY-034/064/065).
# Every filesystem path below is a string literal. What is request-derived
# is the file *contents* — writing tainted bytes to a fixed path is not
# CWE-22.
import os
import shutil

from flask import request, send_file


def append_audit():
    # Constant destination, tainted contents. The literal path also keeps
    # ZS-PY-008 (open() with a non-literal path) quiet.
    note = request.form['note']
    with open('/var/log/app/audit.log', 'a') as handle:
        handle.write(note)


def send_price_list():
    # send_file is pinned to argument 0; the served file is a literal.
    return send_file('static/price-list.pdf')


def purge_upload_slot():
    os.remove('/var/spool/app/current-upload.tmp')


def reset_scratch():
    shutil.rmtree('/var/tmp/app-scratch', ignore_errors=True)
