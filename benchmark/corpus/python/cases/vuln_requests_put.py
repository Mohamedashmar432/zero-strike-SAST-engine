# ZS-PY-073: SSRF — requests.put() to a tainted URL
import requests
url = request.args.get('url')
requests.put(url, data={"k": "v"})
