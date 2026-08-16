from flask import Flask, jsonify

app = Flask(__name__)

USERS = {"1": {"name": "alice"}, "2": {"name": "bob"}}


@app.route("/user/<int:user_id>")
def user(user_id):
    return jsonify(USERS.get(str(user_id)))
