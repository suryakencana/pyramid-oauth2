'''
Database model definitions.

@author: Kevin Van Wilder <kevin@tick.ee>
'''
from pyramid_oauth2.appconsts import ACCESS_TOKEN_LENGTH, REFRESH_TOKEN_LENGTH, \
    CLIENT_KEY_LENGTH, CLIENT_SECRET_LENGTH, ALLOWED_CHARACTERS
from pyramid_oauth2.utils import generate_key
from random import choice
from sqlalchemy.schema import Column, ForeignKey
from sqlalchemy.sql.expression import func
from sqlalchemy.types import Integer, DateTime, String, Boolean
import datetime
import sqlahelper
import sqlalchemy.orm as orm

Base = sqlahelper.get_base()
Session = sqlahelper.get_session()

UNUSABLE_SECRET = "!"

class OAuth2Client(Base):
    __tablename__ = 'oauth2_client'
    
    id = Column(Integer, primary_key=True) # Internal user only    
    key = Column(String(CLIENT_KEY_LENGTH), unique=True)
    secret = Column(String(CLIENT_SECRET_LENGTH))
    name = Column(String(256))
    image_url = Column(String(256))
    redirect_uri = Column(String())
    allowed_scopes = Column(String(256)) # space delimited
    
    created_at = Column(DateTime, default=func.now())
    revoked_at = Column(DateTime)
    tokens_granted = Column(Integer, default=0)
    tokens_revoked = Column(Integer, default=0)
    
    def __init__(self, name, image_url=None, redirect_uri=None):
        """Construct a new ``OAuth2Client`` object"""
        self.name = name
        self.image_url = image_url
        self.redirect_uri = redirect_uri
        self.key = self._generate_unique_key()
        self.set_unusable_secret()
    
    def set_scopes(self, allowed_scopes=[]):
        """Sets the scopes allowed by the client."""
        self.allowed_scopes = ' '.join(allowed_scopes)
    
    def set_unusable_secret(self):
        """Invalidates the secret"""
        self.secret = UNUSABLE_SECRET
    
    def has_usable_secret(self):
        """Checks whether the client has a usable secret."""
        return self.secret != UNUSABLE_SECRET
    
    def set_secret(self, raw_secret):
        """Sets a new secret for the user."""
        import os, base64
        algo = "ssha"
        salt = str.lower(base64.b16encode(os.urandom(4)))
        hsh = self._get_hex_string(algo, salt, raw_secret)
        self.secret = '%s$%s$%s' % (algo, salt, hsh)
    
    def check_secret(self, raw_secret):
        """Validates the raw_secret to the one in the database."""
        if self.has_usable_secret():
            algo, salt, hsh = self.secret.split('$')
            return hsh == self._get_hex_string(algo, salt, raw_secret)
        return False
    
    def revoke(self):
        """Revoke all authorization requests, access grants and access tokens 
        of the ``Client``."""
        self.revoked = datetime.datetime.now()
        # Revoke all authorization requests
        # Revoke all access tokens
        for token in self.tokens:
            token.revoke()
            self.revoked_tokens += 1 

    def _get_hex_string(self, algorithm, salt, raw_secret):
        """Salts and encrypts the raw_secret"""
        if algorithm == 'ssha':
            import base64, hashlib
            raw_salt = base64.b16decode(unicode.upper(salt))
            return hashlib.sha1(raw_secret + raw_salt).hexdigest()
        raise ValueError('Got unknown password algorithm type in password.')

    def _generate_unique_key(self, key_length=CLIENT_KEY_LENGTH):
        """Generates a unique key for the client"""
        while True:
            key_value = generate_key(length=key_length)
            if not Session.query(OAuth2Client).filter_by(key=key_value).count():
                return key_value



class OAuth2AccessToken(Base):
    __tablename__ = 'oauth2_accesstoken'

    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey('oauth2_client.id'))
    client = orm.relation(OAuth2Client, backref="tokens")
    token = Column(String(ACCESS_TOKEN_LENGTH), unique=True)
    refresh_token = Column(String(REFRESH_TOKEN_LENGTH))
    allowed_scopes = Column(String(256)) # space delimited
    issued_at = Column(DateTime)
    expires_at = Column(DateTime)
    revoked_at = Column(DateTime)
    
    def __init__(self, refreshable=True, expires_in=3600, allowed_scopes=[]):
        self.allowed_scopes = ' '.join(allowed_scopes)
        # Generate Access Token
        self.token = self._generate_token(ACCESS_TOKEN_LENGTH)
        # Generate Refresh Token
        if refreshable:
            self.refresh_token = self._generate_token(REFRESH_TOKEN_LENGTH)
        # Expiration
        timedelta = datetime.timedelta(seconds=expires_in)
        self.issued_at = datetime.datetime.now() 
        self.expires_at = self.issued_at + timedelta
        
    
    def revoke(self):
        """Revoke this token so it can not be used for authenticating 
        a client."""
        self.revoked_at = datetime.datetime.now()
           
    def is_revoked(self):
        """Checks whether the access token is revoked."""
        return self.revoked_at is not None     
    
    def expired(self):
        """Returns ``True`` if the datetime from ``expires_at`` is in the past,
        relative to the server's time or it has been revoked."""
        return not self.is_revoked() or self.expires_at < datetime.datetime.now()
    
    def set_scopes(self, scopes):
        self.allowed_scopes = " ".join(scopes)
    
    def get_scopes(self):
        """Returns a list of all scopes allowed by the access token."""
        return self.allowed_scopes.split(' ')
    
    def confirm_authorized_scopes(self, scopes):
        """Validates if the requested scopes are allowed by the access token."""
        allowed_scopes = self.get_scopes()
        for scope in scopes:
            if not scope in allowed_scopes:
                return False
        return True
            
    
    def _generate_token(self, length=ACCESS_TOKEN_LENGTH):
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