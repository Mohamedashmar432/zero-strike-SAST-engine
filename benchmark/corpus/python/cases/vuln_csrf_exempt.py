# ZS-PY-090: a state-changing Django view with CSRF protection switched off.
# The exemption sits under another decorator to prove the whole stack is seen.
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt


@login_required
@csrf_exempt
def transfer(request):
    if request.method == "POST":
        request.user.account.send(request.POST["to"], request.POST["amount"])
    return HttpResponse("ok")
