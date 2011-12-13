from pyramid_oauth2 import Oauth2Context
from pyramid_oauth2.models import OAuth2Client, OAuth2AccessToken
from pyramid_oauth2.oauth2.exceptions import ClientNotFoundError
import logging
import sqlahelper

Session = sqlahelper.get_session()
    
# actions

def register_client(name, image_url=None, redirect_url=None, allowed_scopes=[]):
    """Registers a new client that can request access tokens and access 
    resources."""
    client = OAuth2Client(name)
    Session.add(client)
    client.set_scopes(allowed_scopes)
    Session.flush()
    return client.id

def get_token_context(token):
    """returns information about the token"""
    token_info = Session.query(OAuth2AccessToken).filter_by(token=token).first()
    context = Oauth2Context()
    if token_info:
        valid = not token_info.expired() and not token_info.is_revoked()
        context.scopes = token_info.get_scopes()
        context.client_id = token_info.client_id
        context.valid = valid
    else:
        context.valid = False 
    return context


def is_valid_access_token(token, allowed_scopes):
    """Checks the validity of the access token."""
    # Retrieve token information
    token_info = Session.query(OAuth2AccessToken).filter_by(token=token).first()
    if token_info and not token_info.expired():
        # look for correct scope
        for token_scope in token_info.get_scopes():
            # correct scope found
            if token_scope in allowed_scopes:
                return (True, token_info.client_id, token_scope)
        
    # Bad token
    return (False, None, None)


def authenticate(key, secret):
    """Tries to authenticate a client using its key and secret
    
    Returns tuple (boolean, integer): true and the client_id if successful
    else false and None
    """
    try:
        client = get_client_by_key(key)
    except ClientNotFoundError:
        print("No client found with key: %s" % key)
        return (False, None)
    else:
        if client.check_secret(secret):
            return (True, client.id)
        print type(secret)
        print type(client.secret)
        print("Secret '%s' did not match '%s'" % (secret, client.secret))
        return (False, None)

def can_request_scope(client_id, requested_scopes=[]):
    """Checks if the requested scope can be granted to the client"""
    try:
        client = get_client_by_id(client_id)
    except ClientNotFoundError:
        return False
    else:
        # verify requested scopes
        for requested_scope in requested_scopes:
            if not requested_scope in client.allowed_scopes:
                # scope was not allowed
                return False
        # all scopes were allowed
        return True 


def issue_access_token(client_id, allowed_scopes=[], refreshable=False):
    """Issues an access token to the client"""
    access_token = OAuth2AccessToken(refreshable)
    access_token.set_scopes(allowed_scopes)
    client = get_client_by_id(client_id)
    access_token.client = client
    # Increment granted client tokens
    client.tokens_granted += 1
    Session.add(access_token)
    Session.flush()
    return access_token
    
# internal

def get_client_by_key(key):
    """Fetches the client object belonging to the key"""
    client = Session.query(OAuth2Client).filter(OAuth2Client.key==key).first()
    if not client:
        raise ClientNotFoundError
    return client

def get_client_by_id(id):
    """Fetches the client object belonging to the id"""
    client = Session.query(OAuth2Client).get(id)
    if not client:
        raise ClientNotFoundError
    return client