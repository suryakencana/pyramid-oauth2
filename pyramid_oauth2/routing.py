'''
Created on 20-jul-2011

@author: kevin
'''
from pyramid_oauth2 import views

def configure_oauth2_routing(config):
    # Token end-point
    config.add_route('oauth2-token-endpoint', '/oauth2/token', view=views.token_endpoint)
    # Authorization end-point
    config.add_route('oauth2-auth-endpoint', '/oauth2/auth', view=views.authorization_endpoint)