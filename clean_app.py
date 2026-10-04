def greet(name):
    return "hello " + "".join(c for c in name if c.isalnum())
