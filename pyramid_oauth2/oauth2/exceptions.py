class OAuth2Exception(Exception):
    """Exceptions related to OAuth 2.0"""
    
class ClientNotFound(OAuth2Exception):
    """Client was not found"""