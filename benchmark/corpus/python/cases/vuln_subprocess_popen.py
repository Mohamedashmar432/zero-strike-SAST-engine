# ZS-PY-057: subprocess.Popen() with a tainted command (source: request.args)
import subprocess
cmd = request.args.get('cmd')
subprocess.Popen(cmd, shell=True)
