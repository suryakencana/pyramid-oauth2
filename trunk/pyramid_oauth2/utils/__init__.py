from pyramid_oauth2.appconsts import ALLOWED_CHARACTERS
from random import choice

def generate_key(length=10, allowed_chars=ALLOWED_CHARACTERS):
    return ''.join([choice(allowed_chars) for i in range(length)])