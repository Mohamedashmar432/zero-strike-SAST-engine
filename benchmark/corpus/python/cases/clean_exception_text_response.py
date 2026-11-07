from flask import Response

def view():
    try:
        run()
    except ValueError as exc:
        log(exc)
        return Response('bad request', 400)
