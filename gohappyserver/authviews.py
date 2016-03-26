from flask import abort
from flask import request, jsonify, render_template

from gohappyserver.database import db_session
from gohappyserver.models import User
from gohappyserver.server import app


class AuthResponceCode:
    SUCCESS = 10
    FAIL = 11
    USER_EXISTS = 12

    INVALID_CREDENTIALS = 13


@app.route("/")
def main_page():
    return render_template("index.html")


@app.route("/auth/login", methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    response = {}
    user = User.query.filter_by(username=username).first()
    if not user or not user.verify_password(password):
        response["result"] = AuthResponceCode.FAIL
        response["message"] = AuthResponceCode.INVALID_CREDENTIALS
    else:
        response["result"] = AuthResponceCode.SUCCESS
        response["token"] = user.generate_auth_token().decode('ascii')

    return jsonify(response), 200,


@app.route("/auth/register", methods=["POST"])
def register():
    username = request.form['username']
    password = request.form['password']

    if len(username) == 0 or len(password) == 0:
        abort(400)

    response = {}
    if User.query.filter_by(username=username).first() is not None:
        response["result"] = AuthResponceCode.FAIL
        response["message"] = AuthResponceCode.USER_EXISTS
    else:
        user = User(username=username, password=password)
        db_session.add(user)
        db_session.commit()

        response["result"] = AuthResponceCode.SUCCESS
        response["id"] = user.id
        response["token"] = user.generate_auth_token().decode('ascii')

        print response

    return jsonify(response), 200,


@app.route("/users/online", methods=["GET"])
def list_users():
    token = str(request.headers.get("Authorization")).split(" ")[1]

    if not User.verify_auth_token(token):
        abort(403)

    online_users = User.query.filter(User.socket_id != None)

    return jsonify(online_users), 200,
