class OAuth2Error(Exception):
    """
    Authorization code grant errors
    http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-4.1.2.1

    Implicit grant errors
    http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-4.2.2.1

    Token errors
    http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-5.2
    """
    error = None

    def __init__(self, error_description=None, error_uri=None, state=None):
        super(OAuth2Error, self).__init__(error_description)
        self.error_description = error_description
        self.error_uri = error_uri
        self.state = state

class InvalidRequestError(OAuth2Error):
    error = 'invalid_request'

class UnauthorizedClientError(OAuth2Error):
    error = 'unauthorized_client'

class InvalidClientError(OAuth2Error):
    error = 'invalid_client'

class AccessDeniedError(OAuth2Error):
    error = 'access_denied'

class UnsupportedResponseTypeError(OAuth2Error):
    error = 'unsupported_response_type'

class InvalidGrantError(OAuth2Error):
    error = 'invalid_grant'

class UnsupportedGrantTypeError(OAuth2Error):
    error = 'unsupported_grant_type'

class InvalidScopeError(OAuth2Error):
    error = 'invalid_scope'

class ServerError(OAuth2Error):
    error = 'server_error'

class UnavailableError(OAuth2Error):
    error = 'temporarily_unavailable'
