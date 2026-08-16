from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return query
