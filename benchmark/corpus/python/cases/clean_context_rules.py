# True negatives for the context-aware Python rules (ZS-PY-008, 022, 069,
# 090-099). Every construct here is the safe neighbour of a flagged one.
import glob
import hashlib
import logging
import os
import random
import secrets
from pathlib import Path

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET
from PIL import ImageMath

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "data", "challenge.json")


# ZS-PY-090: an exempt view that only serves GET cannot be forged usefully.
@require_GET
@csrf_exempt
def health(request):
    return HttpResponse("ok")


# ZS-PY-008: constant paths built from __file__ and literals.
def load_data():
    with open(DATA_FILE) as fh:
        first = fh.read()
    here = Path(__file__).resolve().parent
    with open(here / "fixtures" / "seed.json") as fh:
        return first + fh.read()


# ZS-PY-091: a constant glob pattern.
def list_reports():
    return glob.glob(os.path.join(BASE_DIR, "reports", "*.csv"))


# ZS-PY-092: external entities explicitly switched off.
def parser_off(parser, feature_external_ges):
    parser.setFeature(feature_external_ges, False)


# ZS-PY-093: a fixed expression.
def double(img):
    return ImageMath.eval("a * 2", a=img)


# ZS-PY-094 / 095 / 069: small non-security draws and secrets-based tokens.
def roll_dice():
    return random.randint(1, 6)


def generate_token():
    return secrets.token_urlsafe(32)


def jitter():
    return random.getrandbits(8)


# ZS-PY-096: digests of non-password data.
def etag(body):
    return hashlib.sha256(body).hexdigest()


# ZS-PY-097: request content written to a data file, constant code written
# to a module.
def save_note(request):
    note = request.POST.get("note")
    with open(os.path.join(BASE_DIR, "notes", "note.txt"), "w") as out:
        out.write(note)
    with open(os.path.join(BASE_DIR, "generated.py"), "w") as out:
        out.write("VERSION = 1\n")


# ZS-PY-098 / 099: hardened cookie, and clearing calls.
def set_session(response, token):
    response.set_cookie("session", token, httponly=True, secure=True, samesite="Lax")
    response.set_cookie("session", "", max_age=0)
    response.set_cookie("theme", "dark", httponly=True, secure=os.environ.get("HTTPS") == "1")
    return response


# ZS-PY-022: non-sensitive values on logger receivers.
logger = logging.getLogger(__name__)


def audit(user_id, action):
    logger.info(f"user {user_id} did {action}")
    logging.warning("login failed for %s", user_id)
