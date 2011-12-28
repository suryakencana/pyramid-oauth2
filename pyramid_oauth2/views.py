'''
Created on 19-jul-2011

@author: kevin
'''
from pyramid.view import view_config
from pyramid_oauth2.oauth2.authorization import client_credentials_authorization
from pyramid_oauth2.oauth2.errorhandling import OAuth2ErrorHandler
from pyramid_oauth2.resources.request import OAuth2Request


@view_config(route_name='oauth2-auth-endpoint', 
             renderer='json', 
             request_method='GET', 
             http_cache=0)
def authorization_endpoint(request):
    """
    The authorization endpoint is used to interact with the resource
    owner and obtain authorization which is expressed explicitly as an
    authorization code (later exchanged for an access token), or
    implicitly by direct issuance of an access token.
    """
    request = OAuth2Request(request)
    raise NotImplementedError()


@view_config(route_name='oauth2-token-endpoint', 
             renderer='json', 
             request_method='GET',
             http_cache=0)
def token_endpoint(request):
    """
    The token endpoint is used by the client to obtain an access token by
    presenting its authorization grant or refresh token. The token
    endpoint is used with every authorization grant except for the
    implicit grant type (since an access token is issued directly).
    """
    request = OAuth2Request(request)
    
    grant_type = request.params.get('grant_type')
    
    # Authorization Code Grant
    if grant_type == 'authorization_code':
        return OAuth2ErrorHandler.error_unsupported_grant_type()
    # Implicit Grant
    elif grant_type == 'password':
        return OAuth2ErrorHandler.error_unsupported_grant_type() 
    # Client Credentials Grant
    elif grant_type == 'client_credentials':
        scope = request.params.get('scope', '') # Optional
        if scope:
            scope = scope.split(' ')
        # only continue if valid authentication present
        if request.authentication is not None:
            return client_credentials_authorization.delay(request.authentication, scope).get()
    else:
        return OAuth2ErrorHandler.error_unsupported_grant_type()