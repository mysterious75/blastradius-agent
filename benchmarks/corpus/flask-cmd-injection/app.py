from flask import Flask, request

import os

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    cmd = "ping -c 1 " + host
    os.system(cmd)
    return "pong"
