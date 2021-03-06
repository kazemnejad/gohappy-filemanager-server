from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, SignatureExpired, BadSignature
from passlib.apps import custom_app_context as pwd_context
from sqlalchemy import Column, Integer, String, ForeignKey, Boolean
from sqlalchemy.orm import relationship

from gohappyserver import config
from gohappyserver.database import Base, db_session


class User(Base):
    __tablename__ = 'users'
    id = Column("id", Integer, primary_key=True, autoincrement=True)
    username = Column("username", String(50), unique=True, nullable=False)
    password = Column("password", String(200), nullable=False)

    socket_id_as_explorer = Column("e_sid", String(200), unique=True, nullable=True)
    socket_id_as_source = Column("s_sid", String(200), unique=True, nullable=True)

    def __init__(self, username=None, password=None):
        self.username = username
        self.set_password(password)

    def __repr__(self):
        return '<User %r>' % self.username

    def set_password(self, password):
        self.password = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password)

    def generate_auth_token(self):
        s = Serializer(config.SECRET_KEY, expires_in=config.TOKEN_EXPIRATION_TIME)
        return s.dumps({'id': self.id})

    def attach_new_socket(self, sid, is_form_source):
        if is_form_source:
            self.socket_id_as_source = sid
        else:
            self.socket_id_as_explorer = sid

    @staticmethod
    def get_user_by_auth_token(token):
        s = Serializer(config.SECRET_KEY, expires_in=config.TOKEN_EXPIRATION_TIME)
        try:
            data = s.loads(str(token))
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token

        user = User.query.get(data['id'])
        return user

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(config.SECRET_KEY)
        try:
            data = s.loads(token)
        except SignatureExpired:
            return False  # valid token, but expired
        except BadSignature:
            return False  # invalid token

        return 'id' in data


class Session(Base):
    __tablename__ = 'sessions'
    id = Column("id", Integer, primary_key=True, autoincrement=True)
    uuid = Column("uuid", String(100), unique=True, nullable=True)
    enabled = Column("enabled", Boolean, default=False)
    closed = Column("closed", Boolean, default=False)
    explorer_id = Column("explorer_id", Integer, ForeignKey("users.id"), nullable=False)
    source_id = Column("source_id", Integer, ForeignKey("users.id"), nullable=False)

    explorer = relationship("User", foreign_keys=[explorer_id])
    source = relationship("User", foreign_keys=[source_id])

    def __init__(self):
        pass
