from flask import Flask, request

from pymongo import MongoClient

app = Flask(__name__)
db = MongoClient().test


@app.route("/login")
def login():
    user = db.users.find_one({"username": request.args.get("username")})
    return "ok" if user else "denied"
