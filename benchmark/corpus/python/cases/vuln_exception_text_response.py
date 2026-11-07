from flask import Response

def view():
    try:
        run()
    except ValueError as exc:
        return Response(str(exc), 400)
