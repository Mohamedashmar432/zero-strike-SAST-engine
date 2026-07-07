# ZS-PY-015: urllib.request.urlopen() with no allowlist (SSRF)
import urllib.request
resp = urllib.request.urlopen(url)
