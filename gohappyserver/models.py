from itsdangerous import TimedJSONWebSignatureSerializer as Serializer, SignatureExpired, BadSignature
from passlib.apps import custom_app_context as pwd_context
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship

from gohappyserver import config
from gohappyserver.database import Base


class User(Base):
    __tablename__ = 'users'
    id = Column("id", Integer, primary_key=True, autoincrement=True)
    username = Column("username", String(50), unique=True, nullable=False)
    password = Column("password", String(200), nullable=False)

    socket_id = Column("socket_id", String(200), nullable=True)

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

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(config.SECRET_KEY)
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token

        user = User.query.get(data['id'])
        return user


class Session(Base):
    __tablename__ = 'sessions'
    id = Column("id", Integer, primary_key=True, autoincrement=True)
    uuid = Column("uuid", String(100), unique=True)
    explorer_id = Column("explorer_id", Integer, ForeignKey("users.id"), nullable=False)
    source_id = Column("source_id", Integer, ForeignKey("users.id"), nullable=False)

    explorer = relationship("User", foreign_keys=[explorer_id])
    source = relationship("User", foreign_keys=[source_id])
