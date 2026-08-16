from flask import Flask, request

app = Flask(__name__)


@app.route("/redirect")
def redirect():
    next_url = request.args.get("next")
    resp = app.make_response("", 302)
    resp.headers.set("Location", "/go/" + next_url)
    return resp
