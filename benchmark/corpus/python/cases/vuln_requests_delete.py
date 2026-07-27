# ZS-PY-074: SSRF — requests.delete() to a tainted URL
import requests
url = request.args.get('url')
requests.delete(url)
