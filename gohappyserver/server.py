from flask import Flask

from gohappyserver.database import db_session

app = Flask(__name__)

app.debug = True
app.secret_key = "sadkjfhjls dhfjkadsh flkjads"
app.app_context().push()

import gohappyserver.authviews


def run():
    global app
    app.run()


@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()
