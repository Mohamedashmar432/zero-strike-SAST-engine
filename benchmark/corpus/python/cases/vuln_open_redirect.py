# ZS-PY-028: open redirect — target traces back to request.args
target = request.args.get('url')
redirect(target)
