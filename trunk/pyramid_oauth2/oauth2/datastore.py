'''
Created on 19-jul-2011

@author: Kevin Van Wilder <kevin@tick.ee>
'''
from pyramid_oauth2.models import OAuth2Client, OAuth2AccessToken
from pyramid_oauth2.oauth2.exceptions import ClientNotFound
from sqlalchemy.orm.exc import NoResultFound
import sqlahelper

Session = sqlahelper.get_session()


class OAuth2DataStore(object):
    
    def __init__(self):
        self.client_id = None
        self.client_authenticated = False
    
    def register_client(self, name, image_url=None, redirect_url=None, allowed_scopes=[]):
        """Registers a new client that can request access tokens and access 
        resources."""
        client = OAuth2Client(name)
        Session.add(client)
        client.set_scopes(allowed_scopes)
        Session.flush()
        return client.id
    
    def confirm_allowed_scopes(self, scopes):
        """Matches the requested scopes of the client to the database."""
        # Always allow if no scope specified
        if not scopes:
            return True
        # Validate if scopes specified
        if self.client_authenticated:
            client = self.get_client_by_id(self.client_id)
            for scope in scopes:
                if not scope in client.allowed_scopes:
                    # Scope was not allowed
                    return False
            # All scopes were allowed
            return True
        # Client is not authenticated, scopes can not be validated
        return False
    
    def confirm_authentication_credentials(self, authentication):
        """Validates the authentication credentials to the information stored
        in the database."""
        if authentication:
            given_key = authentication.get('client_key')
            given_secret = authentication.get('client_secret')
            # fetch client matching key
            try:
                possible_client = self.get_client_by_key(given_key)
            except NoResultFound:
                # no user found matching key
                return False
            else:
                # user found, match key
                if possible_client.check_secret(given_secret):
                    self.client_id = possible_client.id
                    self.client_authenticated = True
                return self.client_authenticated
        return False
    
    def validate_access_token(self, token, required_scopes=[]):
        """The resource server MUST Validate the access token and ensure it has 
        not expired and that its scope covers the requested resource."""
        access_token = Session.query(OAuth2AccessToken).filter_by(token=token).first()
        # Validate access token
        if access_token and not access_token.expired():
            # Pass if no scopes required
            if required_scopes == []:
                self.client_id = access_token.client_id
                return True
            # Validate token scopes
            for token_scope in access_token.get_scopes():
                if token_scope in required_scopes:
                    self.client_id = access_token.client_id
                    return True
            # Token did not contain a correct scope
            return False
        else:
            return False
    
    def get_client_by_id(self, id):
        """Finds the client matching the client id."""
        client = Session.query(OAuth2Client).get(id)
        if not client:
            raise ClientNotFound()
        return client
    
    def get_client_by_key(self, key):
        """Finds the client matching the client key."""
        q = Session.query(OAuth2Client).filter_by(key=key)
        return q.one()
    
    def issue_access_token(self, client_id, refreshable=True, allowed_scopes=[]):
        """Creates an access token for the client."""
        access_token = OAuth2AccessToken(refreshable)
        access_token.set_scopes(allowed_scopes)
        client = self.get_client_by_id(client_id)
        access_token.client = client
        # Increment granted client tokens
        client.tokens_granted += 1
        Session.add(access_token)
        return access_token