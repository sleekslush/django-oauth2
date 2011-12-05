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
        except KeyError:
            return

        try:
            auth_type, credentials = authorization.split(None, 1)
        except ValueError:
            return

        # Only allow Basic auth. Ignore digest
        if auth_type.lower() != 'basic':
            return

        try:
            credentials = base64.b64decode(credentials).split(':', 1)
            request.basic_auth = BasicAuthCreds(*credentials)
        except TypeError:
            """
            Either the value could not be base64-decoded or it doesn't contain a value
            in the form of username:password, so don't set the basic_auth property on request.
            """
