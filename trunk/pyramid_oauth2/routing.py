'''
Created on 20-jul-2011

@author: kevin
'''

def configure_oauth2_routing(config):
    # Token end-point
    config.add_route('oauth2-token-endpoint', '/oauth2/token')
    # Authorization end-point
    config.add_route('oauth2-auth-endpoint', '/oauth2/auth')
    config.scan('pyramid_oauth2.views')
    return config