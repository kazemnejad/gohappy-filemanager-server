class ServerEvents:
    NEW_CONNECTION = "ask_for_new_connection"
    DISCONNECT = "disconnect"

    NEW_EXPLORATION = "start_new_exploration"
    EXPLORATION_PERMISSION_REQUEST_ANSWER = "permission_answer"
    EXPLORATION_PATH_REQUEST = "path_request"
    EXPLORATION_PATH_REQUEST_RESPONSE = "path_request_response"
    CLOSE_SESSION = "close_session"


class ClientEvents:
    SESSION_CLOSED = "session_closed"
    SESSION_CLOSE_ERROR = "close_session_error"
    CONNECTION_ESTABLISHED = "new_connection_established"


class ExplorerEvents:
    NEW_EXPLORATION_RESULT = "start_new_exploration_result"
    PATH_REQUEST_RESPONSE = "path_request_response"


class SourceEvents:
    ASK_FOR_PERMISSION = "ask_for_permission"
    EXPLORATION_STARTED = "exploration_started"
    PATH_REQUESTED = "source_path_requested"
    PATH_RESPONSE_ERROR = "path_request_response_error"
