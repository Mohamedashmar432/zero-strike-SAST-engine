# ZS-PY-064: os.remove() with a tainted path (arbitrary file deletion)
import os
path = request.args.get('path')
os.remove(path)
