from flask import Flask

from flask.ext.socketio import SocketIO

from gohappyserver import config
from gohappyserver.database import db_session

app = Flask(__name__)

app.debug = True
app.secret_key = config.SECRET_KEY
app.app_context().push()
socketio = SocketIO(app)

import gohappyserver.sockethandlers
import gohappyserver.authviews


def run():
    global socketio
    global app
    socketio.run(app)


@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()
