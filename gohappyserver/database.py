from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

from gohappyserver import config

engine = create_engine('mysql://' + config.db['user'] + ':' + config.db['password'] + '@localhost/gohappy',
                       convert_unicode=True)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()


def init_db():
    import gohappyserver.models
    Base.metadata.create_all(bind=engine)
