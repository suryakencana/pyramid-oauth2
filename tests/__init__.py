from pyramid_oauth2.oauth2.datastore import OAuth2DataStore
import unittest

class TestOAuthDataStore(unittest.TestCase):
    
    def setUp(self):
        pass
    
    def tearDown(self):
        pass
    
    def add_client(self):
        pass
    
    def test_adding_correct_client(self):
        self.add_client()
    
    def test_confirm_authentication_credentials_call(self):
        # Setup
        credentials = dict(client_key="ClientName",
                           client_secret="ClientSecret")
        datastore = OAuth2DataStore()
        # Test
        datastore.confirm_authentication_credentials(credentials)
        
    
    def test_confirm_valid_authentication_credentials(self):
        # Setup
        credentials = dict(client_key="ClientName",
                           client_secret="ClientSecret")
        datastore = OAuth2DataStore()
        datastore.add_client()
        # Test
        datastore.confirm_authentication_credentials(credentials)
        # Validate
    
    def test_confirm_invalid_authentication_credentials(self):
        pass
    
    def test_confirm_malformed_authentication_credentials(self):
        pass


#    def confirm_authentication_credentials(self, authentication):
#        given_key = authentication.get('client_key')
#        given_secret = authentication.get('client_secret')
#        # fetch client matching key
#        possible_client = self.get_client_by_key(given_key)
#        if possible_client.secret == given_secret:
#            self.client_id = possible_client.id
#            self.client_authenticated = True
#        return self.client_authenticated
#    
#    def validate_access_token(self, token, allowed_scope):
#        """
#        The resource server MUST Validate the access token and ensure it has not
#        expired and that its scope covers the requested resource.
#        """
#        access_token = Session.query(OAuth2AccessToken).filter_by(token=token).first()
#        # TODO: validate scope of grant
#        if access_token and not access_token.expired():
#            self.client_id = access_token.client_id
#            return True
#        else:
#            return False
#    
#    def get_client_by_key(self, key):
#        q = Session.query(OAuth2Client).filter_by(key=key)
#        return q.one()
#    
#    def issue_access_token(self, client_id, refreshable=True):
#        access_token = OAuth2AccessToken(client_id, refreshable)
#        Session.add(access_token)
#        return access_token