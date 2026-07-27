# ZS-PY-059: Django ORM raw() with a tainted, concatenated query
name = request.GET.get('name')
query = "SELECT * FROM app_user WHERE name = '" + name + "'"
User.objects.raw(query)
