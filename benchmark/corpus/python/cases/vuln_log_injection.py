# ZS-PY-055: request-supplied value logged verbatim (log injection)
import logging
from flask import request

username = request.args.get('user', '')
logging.info(username)
