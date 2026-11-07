import subprocess

from flask import Flask

web = Flask(__name__)

if __name__ == '__main__':
    subprocess.run(['echo', 'starting'], check=False)
    web.run(host='127.0.0.1', port=5000, debug=False)
