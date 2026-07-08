import subprocess
from flask import request

cmd = request.args.get('cmd')
subprocess.check_output(cmd, shell=True)
