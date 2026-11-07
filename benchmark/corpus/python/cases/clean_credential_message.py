# True negative for ZS-PY-141: a status message passed as a "password" keyword
# is not a credential. (The digest case is covered by an engine test, because
# the secrets scanner has its own opinion about hex strings.)
reply = dict(Password="Updated.")
