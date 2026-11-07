from flask import Flask

vuln_app = Flask(__name__)

if __name__ == '__main__':
    vuln_app.run(host='0.0.0.0', port=5000, debug=True)
