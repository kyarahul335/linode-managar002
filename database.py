import sqlite3
from flask import g

DATABASE = 'keys.db'

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

def init_db(app):
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.executescript(f.read())
        print("Database initialized successfully.")

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()