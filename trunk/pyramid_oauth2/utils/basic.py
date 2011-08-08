'''
Created on 19-jul-2011

Code borrowed from pyramid-oauth project

@author: Kevin Van Wilder <kevin@tick.ee>
'''

import urllib
import string
import time
import random

import hmac
import hashlib
import uuid


available = string.letters + string.digits + '-' + '.' + '_' + '~'

def quote(s):
    return urllib.quote(s, safe=available)

def timestamp():
    return str(int(time.time()))

def nonce():
    return "".join(random.choice(available) for i in xrange(50))

def hmacsha1(key, signature_base):
    hm = hmac.new(key, signature_base, hashlib.sha1)
    return hm.digest().encode('base64').strip()