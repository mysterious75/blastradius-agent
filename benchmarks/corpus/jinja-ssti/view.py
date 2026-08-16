from flask import Flask, request
from jinja2 import Template

app = Flask(__name__)


@app.route("/")
def index():
    tpl = request.args.get("template")
    return Template(tpl).render()
