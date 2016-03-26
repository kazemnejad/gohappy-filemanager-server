import eventlet
from flask import Flask

from flask.ext.socketio import SocketIO

from gohappyserver import config
from gohappyserver.database import db_session

eventlet.monkey_patch()

app = Flask(__name__)

app.debug = True
app.config['SECRET_KEY'] = config.SECRET_KEY
socketio = SocketIO(app, async_mode="eventlet", allow_upgrading=True)

import gohappyserver.sockethandlers
import gohappyserver.authviews


def run():
    global socketio
    global app
    socketio.run(app, "0.0.0.0", 5000)


@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()
