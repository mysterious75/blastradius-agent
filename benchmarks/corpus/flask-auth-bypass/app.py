from flask import Flask, request

app = Flask(__name__)


@app.route("/panel")
def panel():
    role = request.args.get("role")
    if role == "admin":
        return "admin panel"
    return "denied"
