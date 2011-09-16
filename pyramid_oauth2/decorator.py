'''
Created on 26-jul-2011

@author: Kevin Van Wilder <kevin@tick.ee>
'''
from pyramid.httpexceptions import HTTPUnauthorized
from pyramid_oauth2.oauth2 import datastore
from pyramid_oauth2.oauth2.authorization import validate_access_token
from pyramid_oauth2.oauth2.errorhandling import OAuth2ErrorHandler
from pyramid_oauth2.resources.request import OAuth2Request
import logging

def oauth2(allowed_scope=[], mandatory=True):
    def wrap(view_function):
        
        def new_function(*args, **kw):
            handler = args[0]
            handler.request = OAuth2Request(handler.request)
            
            # Validate access token
            if handler.request.access_token:
                access_token = handler.request.access_token.get('token')
                logging.debug("Request contained a token: %s" % access_token)
                valid, client_id = validate_access_token.delay(access_token, allowed_scope).get()
                if valid:
                    # Add client id to the request and execute view
                    logging.debug("Found token linked to client id %s." % client_id)
                    setattr(handler, 'requestor_id', client_id)
                    return view_function(*args, **kw)
                # Request contained invalid access token
                else:
                    logging.debug("Found token appears to be invalid.")
                    if mandatory:
                        return OAuth2ErrorHandler.error_invalid_token(handler.request.access_token.get('type'))
                    else:
                        return view_function(*args, **kw)
            
            # Request does not contain an access token
            else:
                if mandatory:
                    raise HTTPUnauthorized("Request contained no access token.")
                else:
                    return view_function(*args, **kw)
        new_function.__doc__ = view_function.__doc__
        return new_function
    return wrap