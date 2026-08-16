from flask import Flask, request

import pickle

app = Flask(__name__)


@app.route("/data")
def load():
    data = request.args.get("data")
    return pickle.loads(bytes.fromhex(data))
