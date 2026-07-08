from flask import request, send_file

filename = request.args.get('filename')
send_file(filename)
