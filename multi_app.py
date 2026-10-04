import sqlite3


def lookup(name):
    # db password = "supersecret123" (fixture credential for redaction test)
    q = "SELECT * FROM c WHERE pwd='hunter2' AND name = '" + name + "'"
    return q
