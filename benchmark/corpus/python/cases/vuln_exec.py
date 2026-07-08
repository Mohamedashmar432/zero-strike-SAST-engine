from flask import request

plugin_code = request.form['code']
exec(plugin_code)
