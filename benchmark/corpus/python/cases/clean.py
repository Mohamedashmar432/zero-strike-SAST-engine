def greet(name):
    message = "Hello, " + name
    return message

greeting = greet("world")
print(greeting)

# ZS-PY-027 negative case: the template is a fixed literal — only the render
# variable (name) is tainted, so argument_count: 1 must keep this from
# matching (the call has 2 arguments), same fixed-template-plus-tainted-
# variable shape as app.py's own safe_template() false-positive test.
name = request.args.get('name')
render_template_string("<h1>Hello {{ name }}!</h1>", name=name)
