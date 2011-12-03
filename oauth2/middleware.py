import base64

class BasicAuthenticationMiddleware(object):
    def process_request(self, request):
        try:
            authorization = request.META['HTTP_AUTHORIZATION']
        except KeyError:
            return

        try:
            auth_type, credentials = authorization.split(None, 1)
        except ValueError:
            return

        if auth_type.lower() != 'basic':
            return

        request.basic_auth = base64.b64decode(credentials).split(':', 1)
