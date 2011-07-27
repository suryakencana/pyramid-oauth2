'''
Created on 19-jul-2011

@author: kevin
'''
from pyramid.request import Request
import binascii

class OAuth2Request(Request):
    """
    Proxy Class extending a request with information necessary for 
    """
    
    def __init__(self, request):
        self.__subject = request
        # Add OAuth related information from the header to params
        self.authentication = self._get_basic_authentication_credentials(request)
        self.access_token = self._get_access_token(request)
        
    def __getattr__(self, name):
        return getattr(self.__subject, name)
    
    def _get_access_token(self, request):
        """
        Retrieves the access token and the token type from the Authentication 
        header and stores it in a dictionary.
        """
        if not hasattr(request, 'authorization') or request.authorization is None:
            return None
        
        try:
            auth_method, information = request.authorization
        except ValueError: # not enough values to unpack
            return None
        
        if auth_method.lower() == 'bearer':
            token = information.strip()
            return dict(type='bearer',
                        token=token)
        elif auth_method.lower() == 'mac':
            raise NotImplementedError()
            
        return None
    
    def _get_basic_authentication_credentials(self, request):
        """
        Retrieves the user id and password from the Authentication header and
        stores it in a dictionary.
        """
        if not hasattr(request, 'authorization') or request.authorization is None:
            return None

        try:
            auth_method, auth = request.authorization
        except ValueError: # not enough values to unpack
            return None
        
        if auth_method.lower() == 'basic':
            try:
                auth = auth.strip().decode('base64')
            except binascii.Error: # Decode is not possible
                return None
            try:
                key, secret = auth.split(':', 1)
            except ValueError: # not enough values to unpack
                return None
            return dict(type='basic',
                        client_key=key,
                        client_secret=secret)
        
        return None