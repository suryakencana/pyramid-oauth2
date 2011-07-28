'''
Created on 26-jul-2011

@author: Kevin Van Wilder <kevin@tick.ee>
'''
from pyramid.httpexceptions import HTTPUnauthorized
from pyramid_oauth2.oauth2.datastore import OAuth2DataStore
from pyramid_oauth2.oauth2.errorhandling import OAuth2ErrorHandler
from pyramid_oauth2.resources.request import OAuth2Request

def oauth2(allowed_scope=[]):
    def wrap(view_function):
        def new_function(*args, **kw):
            handler = args[0]
            handler.request = OAuth2Request(handler.request)
            
            # Validate access token
            if handler.request.access_token:
                access_token = handler.request.access_token.get('token')
                datastore = OAuth2DataStore()
                valid, client_id = datastore.validate_access_token(access_token, allowed_scope)
                if valid:
                    # Add client id to the request and execute view
                    setattr(handler, 'requestor_id', client_id)
                    return view_function(*args, **kw)
                # No token found or token expired.
                else:
                    return OAuth2ErrorHandler.error_invalid_token(handler.request.access_token.get('type'))
            
            # Request does not contain an access token
            else:
                raise HTTPUnauthorized()
                                
        return new_function
    return wrap



#def oauth_authentication_required(f):
#    """
#    """
#    @functools.wraps(f)
#    def wrapper(*args, **kwds):
#        print "Asserting valid BASIC HTTP authentication:",
#        handler = args[0]
#        # Add OAuth2 to request
#        handler.request = OAuth2Request(handler.request)
#        # Set client identification key in 
#        if handler.request.authentication:           
#            # Check if a Client exists with the given credentials
#            datastore = OAuth2DataStore()
#            confirmation = datastore.confirm_authentication_credentials(handler.request.authentication)
#            handler.requestor_id = get_requestor_account_id(handler.client_key)
#        
#        # 
#        
#        print handler.request.authentication
#        
#        return f(*args, **kwds)
#    
#    
#    
#    return wrapper
#            

