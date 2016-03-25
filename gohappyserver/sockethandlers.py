from flask import request

from flask.ext.socketio import disconnect, emit

from gohappyserver.database import db_session
from gohappyserver.models import User
from gohappyserver.server import socketio
from gohappyserver.status import ResponseCode


@socketio.on("ask_for_new_connection")
def handle_new_connection(data):
    if data is None or "token" not in data:
        disconnect()
        return

    token = data.get("token", "")
    sid = request.sid

    user = User.get_user_by_auth_token(token)
    if user is None:
        disconnect()
        return

    user.attach_new_socket(sid)
    db_session.commit()

    emit("new_connection_established", {"result": ResponseCode.SUCCESSFUL}, room=sid)
