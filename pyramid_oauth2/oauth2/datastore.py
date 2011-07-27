'''
Created on 19-jul-2011

@author: kevin
'''
from pyramid_oauth2.models import OAuth2Client, OAuth2AccessToken
import sqlahelper

Session = sqlahelper.get_session()


class OAuth2DataStore(object):
    
    client_id = None
    client_authenticated = False
    
    def confirm_authentication_credentials(self, authentication):
        given_key = authentication.get('client_key')
        given_secret = authentication.get('client_secret')
        # fetch client matching key
        possible_client = self.get_client_by_key(given_key)
        if possible_client.secret == given_secret:
            self.client_id = possible_client.id
            self.client_authenticated = True
        return self.client_authenticated
    
    def validate_access_token(self, token, allowed_scope):
        """
        The resource server MUST Validate the access token and ensure it has not
        expired and that its scope covers the requested resource.
        """
        print "Looking for token with code=", token
        access_token = Session.query(OAuth2AccessToken).filter_by(token=token).first()
        print "All tokens found=", Session.query(OAuth2AccessToken).all()
        print "Found token in db=", access_token
        # TODO: validate scope of grant
        return access_token and not access_token.expired()
    
    def get_client_by_key(self, key):
        q = Session.query(OAuth2Client).filter_by(key=key)
        return q.one()
    
    def issue_access_token(self, client_id, refreshable=True):
        access_token = OAuth2AccessToken(client_id, refreshable)
        Session.add(access_token)
        return access_token