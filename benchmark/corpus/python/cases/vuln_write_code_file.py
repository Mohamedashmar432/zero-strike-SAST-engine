# ZS-PY-097: form input written into a Python module and into a Django
# template, both of which the application later executes or renders.
import os
import uuid


def save_plugin(request):
    code = request.POST.get("code")
    dirname = os.path.dirname(__file__)
    filename = os.path.join(dirname, "plugins/user_plugin.py")
    f = open(filename, "w")
    f.write(code)
    f.close()


def save_blog(request):
    blog = request.POST["blog"]
    page_id = str(uuid.uuid4())
    path = os.path.join(os.path.dirname(__file__), f"templates/blogs/{page_id}.html")
    with open(path, "w+") as out:
        out.write(blog)
