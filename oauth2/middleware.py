import base64
from collections import namedtuple

BasicAuthCreds = namedtuple('BasicAuthCreds', 'username password')

class BasicAuthenticationMiddleware(object):
    def process_request(self, request):
        """
        Checks for the HTTP_AUTHORIZATION HTTP header and assigns the base64-decoded
        result to the request object.

        The value can be accessed via request.basic_auth, as a tuple with the value
        of (username, password)
        """
        try:
            authorization = request.META['HTTP_AUTHORIZATION']
            auth_type, credentials = authorization.split(None, 1)
        except (KeyError, ValueError):
            return

        self.handle_auth(auth_type, credentials)

    def handle_auth(self, auth_type, credentials):
        """
        Based on the auth type, get a handler and call it so it can handle its
        authorization.
        """
        auth_type_handler = getattr(self, 'handle_{}_auth', None)

        if callable(auth_type_handler):
            auth_type_handler(auth_type, credentials)

    def handle_basic_auth(self, auth_type, credentials):
        try:
            credentials = base64.b64decode(credentials).split(':', 1)
            request.basic_auth = BasicAuthCreds(*credentials)
        except TypeError:
            """
            Either the value could not be base64-decoded or it doesn't contain a value
            in the form of username:password, so don't set the basic_auth property on request.
            """
    
    def handle_bearer_auth(self, auth_type, credentials):
        request.access_token = credentials
