import hashlib
from flask import request

from flask.ext.socketio import disconnect, emit

from events import ServerEvents, ClientEvents, ExplorerEvents, SourceEvents
from gohappyserver.database import db_session
from gohappyserver.models import User, Session
from gohappyserver.server import socketio
from gohappyserver.status import ResponseCode, AuthenticationResponse, ExplorationResponse


@socketio.on(ServerEvents.NEW_CONNECTION)
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

    emit(ClientEvents.CONNECTION_ESTABLISHED, {"result": ResponseCode.SUCCESSFUL}, room=sid)


@socketio.on(ServerEvents.NEW_EXPLORATION)
def handle_start_new_exploration(data):
    sid = request.sid

    if data is None \
            or "token" not in data \
            or "source" not in data:
        simple_response(ExplorerEvents.NEW_EXPLORATION_RESULT, ResponseCode.FAILED,
                        ResponseCode.BAD_REQUEST, sid)
        return

    explorer = User.get_user_by_auth_token(data.get("token", ""))
    source = User.query.filter_by(username=data.get("source", "")).first()
    if explorer is None:
        simple_response(ExplorerEvents.NEW_EXPLORATION_RESULT, ResponseCode.FAILED,
                        AuthenticationResponse.UN_AUTHENTICATED_USER, sid)
        return

    if source is None:
        simple_response(ExplorerEvents.NEW_EXPLORATION_RESULT, ResponseCode.FAILED,
                        AuthenticationResponse.INVALID_SOURCE, sid)
        return

    if source.socket_id is None:
        simple_response(ExplorerEvents.NEW_EXPLORATION_RESULT, ResponseCode.FAILED,
                        ExplorationResponse.SOURCE_IS_OFFLINE, sid)
        return

    session = Session()
    db_session.add(session)
    db_session.commit()

    session.uuid = hashlib.md5(str(session.id)).hexdigest()
    session.explorer = explorer
    session.source = source
    session.enabled = False
    db_session.commit()

    emit(SourceEvents.ASK_FOR_PERMISSION, {"explorer": explorer.username, "session_id": session.uuid},
         room=source.socket_id)


@socketio.on(ServerEvents.EXPLORATION_PERMISSION_REQUEST_ANSWER)
def handle_source_permission_answer(data):
    if data is None \
            or "session_id" not in data \
            or "token" not in data \
            or "answer" not in data:
        return

    session = Session.query.filter_by(uuid=data.get("session_id")).first()
    if session is None:
        return

    source = session.source
    if source is None or source.username != User.get_user_by_auth_token(data.get("token")).username:
        return

    explorer = session.explorer
    if explorer is None \
            or source.socket_id is None \
            or explorer.socket_id is None:
        return

    answer = data.get("answer")
    if answer not in [ExplorationResponse.ANSWER_PERMISSION_GRANTED, ExplorationResponse.ANSWER_PERMISSION_DENIED]:
        simple_response(ExplorerEvents.NEW_EXPLORATION_RESULT,
                        ResponseCode.FAILED, ExplorationResponse.INVALID_ANSWER,
                        explorer.socket_id)
        return

    response = {}
    result = ResponseCode.FAILED
    session.enabled = False
    if answer == ExplorationResponse.ANSWER_PERMISSION_GRANTED:
        result = ResponseCode.SUCCESSFUL
        session.enabled = True

        response["session_id"] = session.uuid
        response["source"] = source.username

    db_session.commit()
    response["result"] = result
    response["answer"] = answer
    response["message"] = answer

    emit(ExplorerEvents.NEW_EXPLORATION_RESULT, response, room=explorer.socket_id)
    emit(SourceEvents.EXPLORATION_STARTED, {"session_id": session.uuid, "explorer": explorer.username},
         room=source.socket_id)


@socketio.on(ServerEvents.EXPLORATION_PATH_REQUEST)
def handle_path_request(data):
    sid = request.sid

    if data is None \
            or "token" not in data \
            or "session_id" not in data \
            or "path" not in data \
            or "request_code" in data:
        simple_response(ExplorerEvents.PATH_REQUEST_RESPONSE, ResponseCode.FAILED,
                        ResponseCode.BAD_REQUEST, sid)
        return

    session = Session.query.filter_by(uuid=data.get("session_id")).first()
    if session is None \
            or not session.enabled \
            or session.explorer is None \
            or session.source is None:
        simple_response(ExplorerEvents.PATH_REQUEST_RESPONSE, ResponseCode.FAILED,
                        ExplorationResponse.INVALID_SESSION, sid)
        return

    explorer = User.get_user_by_auth_token(data.get("token"))
    if explorer is None \
            or explorer.socket_id is None \
            or explorer.socket_id != sid \
            or session.explorer.socket_id != sid:
        simple_response(ExplorerEvents.PATH_REQUEST_RESPONSE, ResponseCode.FAILED,
                        AuthenticationResponse.UN_AUTHENTICATED_USER, sid)
        return

    if session.source.socket_id is None:
        simple_response(ExplorerEvents.PATH_REQUEST_RESPONSE, ResponseCode.FAILED,
                        ExplorationResponse.SOURCE_IS_OFFLINE, sid)
        return

    emit(SourceEvents.PATH_REQUESTED,
         {"request_code": data.get("request_code"), "path": data.get("path"), "session_id": data.get("session_id")},
         room=session.source.socket_id)


@socketio.on(ServerEvents.EXPLORATION_PATH_REQUEST_RESPONSE)
def handle_path_request_response(data):
    sid = request.sid

    if data is None \
            or "token" not in data \
            or "request_code" not in data \
            or "session_id" not in data \
            or "response_data" not in data:
        simple_response(SourceEvents.PATH_RESPONSE_ERROR, ResponseCode.FAILED,
                        ResponseCode.BAD_REQUEST, sid)
        return

    session = Session.query.filter_by(uuid=data.get("session_id")).first()
    if session is None \
            or not session.enabled \
            or session.explorer is None \
            or session.source is None:
        simple_response(SourceEvents.PATH_RESPONSE_ERROR, ResponseCode.FAILED,
                        ExplorationResponse.INVALID_SESSION, sid)
        return

    source = User.get_user_by_auth_token(data.get("token"))
    if source.username != session.source.username \
            or source.socket_id is None \
            or source.socket_id != sid:
        simple_response(SourceEvents.PATH_RESPONSE_ERROR, ResponseCode.FAILED,
                        AuthenticationResponse.PERMISSION_DENIED, sid)
        return

    explorer = session.explorer
    if explorer.socket_id is None:
        simple_response(SourceEvents.PATH_RESPONSE_ERROR, ResponseCode.FAILED,
                        ExplorationResponse.EXPLORER_IS_OFFLINE, sid)
        return

    emit(ExplorerEvents.PATH_REQUEST_RESPONSE,
         {"request_code": data.get("request_code"), "session_id": data.get("session_id"),
          "response_data": data.get("response_data")},
         room=explorer.socket_id)


@socketio.on(ServerEvents.CLOSE_SESSION)
def handle_close_session(data):
    sid = request.sid

    if data is None \
            or "token" not in data \
            or "session_id" not in data:
        simple_response(ClientEvents.SESSION_CLOSE_ERROR, ResponseCode.FAILED,
                        ResponseCode.BAD_REQUEST, sid)
        return

    session = Session.query.filter_by(uuid=data.get("session_id")).first()
    if session is None \
            or session.closed \
            or session.source is None \
            or session.explorer is None:
        simple_response(ClientEvents.SESSION_CLOSE_ERROR, ResponseCode.FAILED,
                        ExplorationResponse.INVALID_SESSION, sid)
        return

    user = User.get_user_by_auth_token(data.get("token"))
    if user is None \
            or (user.username != session.explorer.username and user.username != session.source.username):
        simple_response(ClientEvents.SESSION_CLOSE_ERROR, ResponseCode.FAILED,
                        AuthenticationResponse.PERMISSION_DENIED, sid)
        return

    close_session(session)
    db_session.commit()


@socketio.on(ServerEvents.DISCONNECT)
def handle_disconnect():
    sid = request.sid
    if not sid: return

    user = User.query.filter_by(socket_id=sid).first()
    if user:
        user.attach_new_socket(None)

        sessions = Session.query.filter_by(source=user)
        for session in sessions:
            close_session(session)

        sessions = Session.query.filter_by(explorer=user)
        for session in sessions:
            close_session(session)

        db_session.commit()


def simple_response(event, resultCode, message, sid):
    emit(
            event,
            {"result": resultCode, "message": message},
            room=sid
    )


def close_session(session):
    session.enabled = False
    session.closed = True

    emit(ClientEvents.SESSION_CLOSED, {"session_id": session.uuid}, room=session.explorer.socket_id)
    emit(ClientEvents.SESSION_CLOSED, {"session_id": session.uuid}, room=session.source.socket_id)
