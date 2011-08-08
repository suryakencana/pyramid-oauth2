'''
Created on 20-jul-2011

@author: kevin
'''
from pyramid_oauth2.oauth2.datastore import OAuth2DataStore
from pyramid_oauth2.oauth2.errorhandling import OAuth2ErrorHandler
import transaction

def client_credentials_authorization(auth_credentials, scopes=[]):
    """
    The client can request an access token using only its client
    credentials (or other supported means of authentication) when the
    client is requesting access to the protected resources under its
    control, or those of another resource owner which has been previously
    arranged with the authorization server (the method of which is beyond
    the scope of this specification).
    
    The client credentials grant type MUST only be used by private
    clients.
    
    +---------+                                  +---------------+
    |         |                                  |               |
    |         |>--(A)- Client Authentication --->| Authorization |
    | Client  |                                  |    Server     |
    |         |<--(B)---- Access Token ---------<|               |
    |         |                                  |               |
    +---------+                                  +---------------+
    
                 Figure 6: Client Credentials Flow
                 
                 
    The flow illustrated in Figure 6 includes the following steps:
    
    (A)  The client authenticates with the authorization server and
         requests an access token from the token endpoint.
    (B)  The authorization server authenticates the client, and if valid
         issues an access token.

    Authorization Request and Response
    ----------------------------------
    
    Since the client authentication is used as the authorization grant,
    no additional authorization request is needed.    
    """
    
    # Authentication
    datastore = OAuth2DataStore()
    authenticated = datastore.confirm_authentication_credentials(auth_credentials)
    
    if authenticated:
        # Validate allowed 
        allowed = datastore.confirm_allowed_scopes(scopes)
        if allowed:
            client_id = datastore.client_id
            access_token = datastore.issue_access_token(client_id=client_id,
                                                        refreshable=False)
            response = dict(access_token=access_token.token,
                            token_type="bearer",
                            expires_in=access_token.expires_at.isoformat())
            transaction.commit()
            return response
        else:
            # Scope was not allowed
            return OAuth2ErrorHandler.error_invalid_scope()
    else:
        # Client not authorized
        return OAuth2ErrorHandler.error_unauthorized_client()