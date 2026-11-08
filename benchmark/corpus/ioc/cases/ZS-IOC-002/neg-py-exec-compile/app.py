src = open('plugin.py').read()
exec(compile(src, 'plugin.py', 'exec'))
