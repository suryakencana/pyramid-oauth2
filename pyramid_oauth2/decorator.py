'''
Created on 26-jul-2011

@author: Kevin Van Wilder <kevin@tick.ee>
'''
from pyramid.httpexceptions import HTTPUnauthorized
from pyramid_oauth2.oauth2.authorization import get_token_context
from pyramid_oauth2.oauth2.errorhandling import OAuth2ErrorHandler
from pyramid_oauth2.resources.request import OAuth2Request

def oauth2(allowed_scopes=[],
           optional=False):
    def wrap(view_fn):
        def new_fn(request):
            # get token
            request = OAuth2Request(request)
            token = request.access_token
            # handle token
            if token:
                oauth2_context = get_token_context.delay(token.get('token')).get()
                # stop if token contains no valid information
                if not oauth2_context.valid:
                    raise OAuth2ErrorHandler.error_invalid_token(token.get('type'))
                # not mandatory use of oauth, but valid token
                if optional:
                    return view_fn(request, oauth2_context)
                # validate scope
                elif has_valid_scope(oauth2_context.scopes, allowed_scopes):
                    return view_fn(request, oauth2_context)
                # return oauth error for invalid token
                else:
                    return OAuth2ErrorHandler.error_invalid_token(token.get('type'))
            # no token
            else:
                if optional:
                    return view_fn(request)
                else:
                    raise HTTPUnauthorized('request contained no access token.')
            
        new_fn.__doc__ = view_fn.__doc__
        new_fn.__name__ = view_fn.__name__
        return new_fn
    return wrap



def has_valid_scope(scopes, allowed_scopes):
    for token_scope in scopes:
        if token_scope in allowed_scopes:
            return True
    return False


#def oauth2(allowed_scope=[], mandatory=True):
#    def wrap(view_function):
#        
#        def new_function(*args, **kw):
#            handler = args[0]
#            handler.request = OAuth2Request(handler.request)
#            
#            # Validate access token
#            if handler.request.access_token:
#                access_token = handler.request.access_token.get('token')
#                logging.debug("Request contained a token: %s" % access_token)
#                valid, client_id, scope = validate_access_token.delay(access_token, allowed_scope).get()
#                if valid:
#                    # Add client id to the request and execute view
#                    logging.debug("Found token linked to client id %s." % client_id)
#                    setattr(handler, 'requestor_id', client_id)
#                    setattr(handler, 'scope', scope)
#                    return view_function(*args, **kw)
#                # Request contained invalid access token
#                else:
#                    logging.debug("Found token appears to be invalid.")
#                    if mandatory:
#                        return OAuth2ErrorHandler.error_invalid_token(handler.request.access_token.get('type'))
#                    else:
#                        return view_function(*args, **kw)
#            
#            # Request does not contain an access token
#            else:
#                if mandatory:
#                    raise HTTPUnauthorized("Request contained no access token.")
#                else:
#                    return view_function(*args, **kw)
#        new_function.__doc__ = view_function.__doc__
#        return new_function
#    return wrap