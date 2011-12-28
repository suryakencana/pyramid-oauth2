'''
Created on 20-jul-2011

@author: kevin
'''
from celery.task import task
from pyramid_oauth2.oauth2 import datastore
from pyramid_oauth2.oauth2.errorhandling import OAuth2ErrorHandler
import logging
import transaction

@task
def validate_access_token(access_token, allowed_scopes):
    return datastore.is_valid_access_token(access_token, allowed_scopes)
    
@task
def get_token_context(token):
    return datastore.get_token_context(token)

@task
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
    logging.debug("Starting client_credentials workflow")
    logging.debug("Requested scopes: %s" % scopes)
    
    if auth_credentials is None:
        return OAuth2ErrorHandler.error_unauthorized_client()
    
    authenticated, client_id = datastore.authenticate(auth_credentials.get('client_key'),
                                                      auth_credentials.get('client_secret'))
    if authenticated:
        # Validate allowed 
        allowed = datastore.can_request_scope(client_id, scopes)
        if allowed:
            logging.debug("Authentication allowed, issueing token.")
            access_token = datastore.issue_access_token(client_id=client_id,
                                                        allowed_scopes=scopes,
                                                        refreshable=False)
            response = dict(access_token=access_token.token,
                            token_type="bearer",
                            expires_in=access_token.expires_at.isoformat())
            transaction.commit()
            return response
        else:
            logging.debug("One or more scopes were not allowed: %s" % scopes)
            # Scope was not allowed
            return OAuth2ErrorHandler.error_invalid_scope()
    else:
        logging.debug("Client is not authorized to ask tokens.")
        # Client not authorized
        return OAuth2ErrorHandler.error_unauthorized_client()