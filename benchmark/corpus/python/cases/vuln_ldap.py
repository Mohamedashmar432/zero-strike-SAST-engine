import ldap3
from flask import request

server = ldap3.Server('ldap://localhost:389')
conn = ldap3.Connection(server, auto_bind=True)

username = request.args.get('username', '')
search_filter = f"(uid={username})"
conn.search('dc=example,dc=com', search_filter)
