# ZS-PY-013: os.popen() with a tainted argument (source: request.args)
cmd = request.args.get('cmd')
os.popen(cmd)
