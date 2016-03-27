import hashlib
from flask import request

from flask.ext.socketio import disconnect, emit

from gohappyserver.database import db_session
from gohappyserver.events import ServerEvents, ClientEvents, ExplorerEvents, SourceEvents
from gohappyserver.models import User, Session
from gohappyserver.server import socketio
from gohappyserver.status import ResponseCode, AuthenticationResponse, ExplorationResponse


@socketio.on('connect')
def test_message():
    print "manual_pong on sid=" + request.sid
    emit('manual_pong', {'data': 'got it!'}, room=request.sid)


@socketio.on(ServerEvents.NEW_CONNECTION)
def handle_new_connection(data):
    if data is None \
            or EventFields.TOKEN not in data \
            or EventFields.CLIENT_TYPE not in data:
        disconnect()
        return

    token = data.get(EventFields.TOKEN, "")
    sid = request.sid

    user = User.get_user_by_auth_token(token)
    if user is None:
        disconnect()
        return

    if user.socket_id_as_source == sid or user.socket_id_as_explorer == sid:
        disconnect()
        return

    is_from_source = data.get(EventFields.CLIENT_TYPE) == EventFields.SOURCE
    user.attach_new_socket(sid, is_from_source)
    db_session.commit()

    emit(ClientEvents.CONNECTION_ESTABLISHED, {EventFields.RESULT: ResponseCode.SUCCESSFUL}, room=sid)


@socketio.on(ServerEvents.NEW_EXPLORATION)
def handle_start_new_exploration(data):
    sid = request.sid

    if data is None \
            or EventFields.TOKEN not in data \
            or EventFields.SOURCE not in data:
        simple_response(ExplorerEvents.NEW_EXPLORATION_RESULT, ResponseCode.FAILED,
                        ResponseCode.BAD_REQUEST, sid)
        return

    explorer = User.get_user_by_auth_token(data.get(EventFields.TOKEN, ""))
    source = User.query.filter_by(username=data.get(EventFields.SOURCE, "")).first()
    if explorer is None:
        simple_response(ExplorerEvents.NEW_EXPLORATION_RESULT, ResponseCode.FAILED,
                        AuthenticationResponse.UN_AUTHENTICATED_USER, sid)
        return

    if source is None:
        simple_response(ExplorerEvents.NEW_EXPLORATION_RESULT, ResponseCode.FAILED,
                        AuthenticationResponse.INVALID_SOURCE, sid)
        return

    if source.socket_id_as_source is None:
        simple_response(ExplorerEvents.NEW_EXPLORATION_RESULT, ResponseCode.FAILED,
                        ExplorationResponse.SOURCE_IS_OFFLINE, sid)
        return

    session = Session()
    db_session.add(session)

    session.explorer = explorer
    session.source = source
    session.enabled = False
    db_session.commit()

    session.uuid = hashlib.md5(str(session.id)).hexdigest()
    db_session.commit()

    emit(SourceEvents.ASK_FOR_PERMISSION,
         {EventFields.EXPLORER: explorer.username, EventFields.SESSION_ID: session.uuid},
         room=source.socket_id_as_source)


@socketio.on(ServerEvents.EXPLORATION_PERMISSION_REQUEST_ANSWER)
def handle_source_permission_answer(data):
    if data is None \
            or EventFields.SESSION_ID not in data \
            or EventFields.TOKEN not in data \
            or EventFields.ANSWER not in data:
        return

    session = Session.query.filter_by(uuid=data.get(EventFields.SESSION_ID)).first()
    if session is None:
        return

    source = session.source
    if source is None or source.username != User.get_user_by_auth_token(data.get(EventFields.TOKEN)).username:
        return

    explorer = session.explorer
    if explorer is None \
            or source.socket_id_as_source is None \
            or explorer.socket_id_as_explorer is None:
        return

    answer = data.get(EventFields.ANSWER)
    if answer not in [ExplorationResponse.ANSWER_PERMISSION_GRANTED, ExplorationResponse.ANSWER_PERMISSION_DENIED]:
        simple_response(ExplorerEvents.NEW_EXPLORATION_RESULT,
                        ResponseCode.FAILED, ExplorationResponse.INVALID_ANSWER,
                        explorer.socket_id_as_explorer)
        return

    response = {}
    result = ResponseCode.FAILED
    session.enabled = False
    if answer == ExplorationResponse.ANSWER_PERMISSION_GRANTED:
        result = ResponseCode.SUCCESSFUL
        session.enabled = True

        response[EventFields.SESSION_ID] = session.uuid
        response[EventFields.SOURCE] = source.username

        emit(SourceEvents.EXPLORATION_STARTED,
             {EventFields.SESSION_ID: session.uuid, EventFields.EXPLORER: explorer.username},
             room=source.socket_id_as_source)

    db_session.commit()
    response[EventFields.RESULT] = result
    response[EventFields.ANSWER] = answer
    response[EventFields.MESSAGE] = answer

    emit(ExplorerEvents.NEW_EXPLORATION_RESULT, response, room=explorer.socket_id_as_explorer)


@socketio.on(ServerEvents.EXPLORATION_PATH_REQUEST)
def handle_path_request(data):
    sid = request.sid

    if data is None \
            or EventFields.TOKEN not in data \
            or EventFields.SESSION_ID not in data \
            or EventFields.PATH not in data \
            or EventFields.REQUEST_CODE not in data:
        simple_response(ExplorerEvents.PATH_REQUEST_RESPONSE, ResponseCode.FAILED,
                        ResponseCode.BAD_REQUEST, sid)
        return

    session = Session.query.filter_by(uuid=data.get(EventFields.SESSION_ID)).first()
    if session is None \
            or not session.enabled \
            or session.explorer is None \
            or session.source is None:
        simple_response(ExplorerEvents.PATH_REQUEST_RESPONSE, ResponseCode.FAILED,
                        ExplorationResponse.INVALID_SESSION, sid)
        return

    explorer = User.get_user_by_auth_token(data.get(EventFields.TOKEN))
    if explorer is None \
            or explorer.socket_id_as_explorer is None \
            or explorer.socket_id_as_explorer != sid \
            or session.explorer.socket_id_as_explorer != sid:
        print sid
        print explorer.socket_id_as_explorer
        print session.explorer.socket_id_as_explorer
        simple_response(ExplorerEvents.PATH_REQUEST_RESPONSE, ResponseCode.FAILED,
                        AuthenticationResponse.UN_AUTHENTICATED_USER, sid)
        return

    if session.source.socket_id_as_source is None:
        simple_response(ExplorerEvents.PATH_REQUEST_RESPONSE, ResponseCode.FAILED,
                        ExplorationResponse.SOURCE_IS_OFFLINE, sid)
        return

    emit(SourceEvents.PATH_REQUESTED,
         {EventFields.REQUEST_CODE: data.get(EventFields.REQUEST_CODE),
          EventFields.PATH: data.get(EventFields.PATH),
          EventFields.SESSION_ID: data.get(EventFields.SESSION_ID)},
         room=session.source.socket_id_as_source)


@socketio.on(ServerEvents.EXPLORATION_PATH_REQUEST_RESPONSE)
def handle_path_request_response(data):
    sid = request.sid

    print "data: " + str(data.get(EventFields.RESPONSE_DATA))

    if data is None \
            or EventFields.TOKEN not in data \
            or EventFields.REQUEST_CODE not in data \
            or EventFields.SESSION_ID not in data \
            or EventFields.RESPONSE_DATA not in data:
        simple_response(SourceEvents.PATH_RESPONSE_ERROR, ResponseCode.FAILED,
                        ResponseCode.BAD_REQUEST, sid)
        return

    session = Session.query.filter_by(uuid=data.get(EventFields.SESSION_ID)).first()
    if session is None \
            or not session.enabled \
            or session.explorer is None \
            or session.source is None:
        simple_response(SourceEvents.PATH_RESPONSE_ERROR, ResponseCode.FAILED,
                        ExplorationResponse.INVALID_SESSION, sid)
        return

    source = User.get_user_by_auth_token(data.get(EventFields.TOKEN))
    if source.username != session.source.username \
            or source.socket_id_as_source is None \
            or source.socket_id_as_source != sid:
        simple_response(SourceEvents.PATH_RESPONSE_ERROR, ResponseCode.FAILED,
                        AuthenticationResponse.PERMISSION_DENIED, sid)
        return

    explorer = session.explorer
    if explorer.socket_id_as_explorer is None:
        simple_response(SourceEvents.PATH_RESPONSE_ERROR, ResponseCode.FAILED,
                        ExplorationResponse.EXPLORER_IS_OFFLINE, sid)
        return

    emit(ExplorerEvents.PATH_REQUEST_RESPONSE,
         {
             EventFields.RESULT: ResponseCode.SUCCESSFUL,
             EventFields.REQUEST_CODE: data.get(EventFields.REQUEST_CODE),
             EventFields.SESSION_ID: data.get(EventFields.SESSION_ID),
             EventFields.RESPONSE_DATA: data.get(EventFields.RESPONSE_DATA)
         },
         room=explorer.socket_id_as_explorer)


@socketio.on(ServerEvents.CLOSE_SESSION)
def handle_close_session(data):
    sid = request.sid

    if data is None \
            or EventFields.TOKEN not in data \
            or EventFields.SESSION_ID not in data:
        simple_response(ClientEvents.SESSION_CLOSE_ERROR, ResponseCode.FAILED,
                        ResponseCode.BAD_REQUEST, sid)
        return

    session = Session.query.filter_by(uuid=data.get(EventFields.SESSION_ID)).first()
    if session is None \
            or session.closed \
            or session.source is None \
            or session.explorer is None:
        simple_response(ClientEvents.SESSION_CLOSE_ERROR, ResponseCode.FAILED,
                        ExplorationResponse.INVALID_SESSION, sid)
        return

    user = User.get_user_by_auth_token(data.get(EventFields.TOKEN))
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

    is_source_client = True
    user = User.query.filter_by(socket_id_as_source=sid).first()
    if user is None:
        is_source_client = False
        user = User.query.filter_by(socket_id_as_explorer=sid).first()

    if user:
        user.attach_new_socket(None, is_source_client)

        if is_source_client:
            sessions = Session.query.filter_by(source=user)
            for session in sessions:
                close_session(session)
        else:
            sessions = Session.query.filter_by(explorer=user)
            for session in sessions:
                close_session(session)

        db_session.commit()


def simple_response(event, resultCode, message, sid):
    emit(
            event,
            {EventFields.RESULT: resultCode, EventFields.MESSAGE: message},
            room=sid
    )


def close_session(session):
    session.enabled = False
    session.closed = True

    emit(ClientEvents.SESSION_CLOSED, {EventFields.SESSION_ID: session.uuid},
         room=session.explorer.socket_id_as_explorer)
    emit(ClientEvents.SESSION_CLOSED, {EventFields.SESSION_ID: session.uuid}, room=session.source.socket_id_as_source)


class EventFields:
    ANSWER = "answer"
    RESULT = "result"
    MESSAGE = "message"

    TOKEN = "token"
    SESSION_ID = "session_id"
    SOURCE = "source"
    EXPLORER = "explorer"

    REQUEST_CODE = "request_code"
    RESPONSE_DATA = "response_data"
    PATH = "path"

    CLIENT_TYPE = "client_type"
