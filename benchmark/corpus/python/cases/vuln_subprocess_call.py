# ZS-PY-012: subprocess.call() with a tainted argument (source: request.args)
import subprocess
cmd = request.args.get('cmd')
subprocess.call(cmd)
