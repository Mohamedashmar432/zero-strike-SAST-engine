# ZS-PY-025: SSRF via requests.get() with a tainted URL (source: request.args)
url = request.args.get('url')
resp = requests.get(url)
