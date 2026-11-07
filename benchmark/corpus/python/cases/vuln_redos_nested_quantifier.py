import re

def check(request):
    return re.search(r"^(a+)+$", request.args.get('v'))
