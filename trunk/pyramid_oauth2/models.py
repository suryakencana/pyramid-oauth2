'''
Database model definitions.

@author: Kevin Van Wilder <kevin@tick.ee>
'''
from pyramid_oauth2.appconsts import ACCESS_TOKEN_LENGTH, REFRESH_TOKEN_LENGTH, \
    CLIENT_KEY_LENGTH, CLIENT_SECRET_LENGTH, ALLOWED_CHARACTERS
from random import choice
from sqlalchemy.schema import Column, ForeignKey
from sqlalchemy.types import Integer, DateTime, String
import datetime
import sqlahelper
import sqlalchemy.orm as orm

Base = sqlahelper.get_base()
Session = sqlahelper.get_session()

class OAuth2Client(Base):
    __tablename__ = 'oauth2_client'
    
    id = Column(Integer, primary_key=True) # Internal user only    
    key = Column(String(CLIENT_KEY_LENGTH), unique=True)
    secret = Column(String(CLIENT_SECRET_LENGTH), unique=True)
    name = Column(String(256))
    image_url = Column(String(256))
    redirect_uri = Column(String())
    
    created_at = Column(DateTime)
    revoked_at = Column(DateTime)
    tokens_granted = Column(Integer)
    tokens_revoked = Column(Integer)
    
    def __init__(self, name, image_url=None, redirect_url=None):
        """
        Construct a new ``OAuth2Client`` object
        """
        self.name = name
        self.image_url = image_url
        self.redirect_url = redirect_url
        self.created_at = datetime.datetime.now()
    
    def set_secret(self, raw_secret):
        # TODO: This should obviously be encoded
        self.secret = raw_secret
    
    def revoke(self):
        """
        Revoke all authorization requests, access grants and access tokens 
        of the ``Client``.
        """
        self.revoked = datetime.datetime.now()
        # Revoke all authorization requests
        # Revoke all access grants
        # Revoke all access tokens

class OAuth2AccessToken(Base):
    __tablename__ = 'oauth2_accesstoken'

    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey('oauth2_client.id'))
    client = orm.relation(OAuth2Client)
    token = Column(String(ACCESS_TOKEN_LENGTH), unique=True)
    refresh_token = Column(String(REFRESH_TOKEN_LENGTH))
    issued_at = Column(DateTime)
    expires_in = Column(DateTime)
    
    def __init__(self, client_id, refreshable=True, expires_in=3600):
        self.client_id = client_id
        # Generate Access Token
        self.token = self.generate_token(ACCESS_TOKEN_LENGTH)
        # Generate Refresh Token
        if refreshable:
            self.refresh_token = self.generate_token(REFRESH_TOKEN_LENGTH)
        # Expiration
        timedelta = datetime.timedelta(seconds=expires_in)
        self.issued_at = datetime.datetime.now() 
        self.expires_in = self.issued_at + timedelta
        
    
    def expired(self):
        """
        Returns ``True`` if the datetime from ``expires_in`` is in the past,
        relative to the server's time.
        """
        return self.expires_in < datetime.datetime.now()
    
    def generate_token(self, length=ACCESS_TOKEN_LENGTH):
        token = self._generate_random_token(length=length)
        while self._exists_already(token):
            token = self._generate_random_token()
        return token
            
    def _generate_random_token(self, length, 
                               allowed_chars=ALLOWED_CHARACTERS):
        return ''.join([choice(allowed_chars) for i in range(length)])
    
    def _exists_already(self, key):
        q = Session.query(self.__class__).filter_by(token=key)
        return q.count() > 0
    
    
    
def initialize_sql(engine):
    Session.configure(bind=engine)
    Base.metadata.bind = engine
    Base.metadata.create_all(engine)