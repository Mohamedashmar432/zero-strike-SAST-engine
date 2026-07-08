# ZS-PY-026: SSRF via requests.post() with a tainted URL (source: request.args)
callback_url = request.args.get('callback')
requests.post(callback_url, json={'data': 'test'})
