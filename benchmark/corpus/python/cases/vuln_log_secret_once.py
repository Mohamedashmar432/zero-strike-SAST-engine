# ZS-PY-022: a request-supplied token logged verbatim. One finding per call
# site: ZS-PY-055 (log injection) stands aside when the argument is
# credential-shaped, so this call is not also reported as CWE-117.
import logging
from flask import request

token = request.args.get('token', '')
logging.info(token)
