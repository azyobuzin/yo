# -*- coding: utf-8 -*-

from datetime import datetime
import flask
from flask_wtf.csrf import CSRFProtect
import os
import tweepy
import sqlite3
import uuid

app = flask.Flask(__name__)
app.secret_key = os.environ.get("YO_SECRET_KEY", uuid.uuid4().hex)
csrf = CSRFProtect(app)

consumer_key = os.environ.get("YO_API_KEY", "CHmR87OMP3PghQdkdm6303a5w")
consumer_secret = os.environ.get("YO_API_SECRET", "rSgMr9g70PnjIWuN2HxQHAoOMIyTcNqRyzt8xiODYINhuTyP8I")

@app.before_request
def before_request():
    flask.session.permanent = True

def connect_db():
    conn = sqlite3.connect(
        os.environ.get("YO_DATABASE", "yo.sqlite3"),
        detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES
    )
    conn.executescript("""
        BEGIN TRANSACTION;
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            screen_name TEXT NOT NULL,
            profile_image TEXT NOT NULL,
            oauth_token TEXT NOT NULL,
            oauth_token_secret TEXT NOT NULL,
            created_at timestamp NOT NULL
        );
        CREATE TABLE IF NOT EXISTS yos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user INTEGER NOT NULL,
            text TEXT NOT NULL,
            created_at timestamp NOT NULL
        );
        COMMIT TRANSACTION;
    """)
    return conn

@app.route("/")
def index():
    conn = connect_db()
    try:
        cursor = conn.cursor()
        logged_in = False
        screen_name = None
        profile_image = None
        if "user" in flask.session:
            cursor.execute("SELECT screen_name, profile_image FROM users WHERE id = ?", (int(flask.session["user"]),))
            user = cursor.fetchone()
            if user:
                logged_in = True
                screen_name = user[0]
                profile_image = user[1]

        max_id = flask.request.values.get("max_id")
        query = "SELECT yos.id, yos.text, yos.created_at, users.screen_name, users.profile_image FROM yos INNER JOIN users ON yos.user = users.id"
        if max_id:
            query += " WHERE yos.id <= " + str(int(max_id))
        query += " ORDER BY yos.id DESC LIMIT 21"
        cursor.execute(query)
        result = cursor.fetchall()
    finally:
        conn.close()
    has_next = len(result) > 20
    if has_next:
        max_id = result[-1][0]
        result = result[:-1]
    return flask.render_template('index.html',
                            logged_in = logged_in,
                            profile_image = profile_image,
                            screen_name = screen_name,
                            yos = result,
                            has_next = has_next,
                            max_id = max_id)

@app.route("/authorize")
def authorize():
    scheme = flask.request.headers.get("X-Forwarded-Proto") or ("https" if flask.request.url.startswith("https://") else "http")
    host = flask.request.headers.get("X-Forwarded-Host") or flask.request.headers.get("Host")
    auth = tweepy.OAuthHandler(consumer_key, consumer_secret, "{}://{}/callback".format(scheme, host))
    redirect_url = auth.get_authorization_url(True)
    flask.session["request_token"] = auth.request_token
    return flask.redirect(redirect_url)

@app.route("/callback")
def callback():
    oauth_token = flask.request.values.get("oauth_token")
    oauth_verifier = flask.request.values.get("oauth_verifier")
    if not oauth_token or not oauth_verifier:
        flask.abort(400)

    request_token = flask.session.get("request_token")
    if not request_token:
        flask.abort(403)
    del flask.session["request_token"]

    auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
    auth.request_token = request_token
    auth.get_access_token(oauth_verifier)

    api = tweepy.API(auth)
    user = api.verify_credentials()

    conn = connect_db()
    try:
        conn.execute("""
            INSERT OR REPLACE
            INTO users (id, screen_name, profile_image, oauth_token, oauth_token_secret, created_at)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (user.id, user.screen_name, user.profile_image_url_https, auth.access_token, auth.access_token_secret, datetime.now()))
        conn.commit()
    finally:
        conn.close()

    flask.session["user"] = user.id

    return flask.redirect(flask.url_for("index"))

@app.route("/logout")
def logout():
    del flask.session["user"]
    return flask.redirect(flask.url_for("index"))

@app.route("/yo", methods=["POST"])
def yo():
    user = flask.session["user"]
    if not user:
        flask.Abort(401)
    
    conn = connect_db()
    try:
        conn.execute("INSERT INTO yos (user, text, created_at) VALUES (?, ?, ?)",
            (user, flask.request.values.get("text", "Yo"), datetime.now()))
        conn.commit()
    finally:
        conn.close()

    return flask.redirect(flask.url_for("index"))

if __name__ == "__main__":
    app.run()
