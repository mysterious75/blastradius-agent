from flask import Flask, request

app = Flask(__name__)


@app.route("/read")
def read():
    path = request.args.get("path")
    return open(path).read()
