def greet(name):
    message = "Hello, " + name
    return message

def process_input(user_input):
    result = eval(user_input)
    return result

greeting = greet("world")
print(greeting)
