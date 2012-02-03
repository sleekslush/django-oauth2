from oauth2.exceptions import *
from oauth2.models import AuthorizationToken, ClientApplication, RefreshToken
from urllib import urlencode
from urlparse import parse_qs, urlparse, urlunparse

class OAuth2Provider(object):
    def __init__(self, client_id, client_secret=None, redirect_uri=None):
        """
        Constructs an OAuth2 provider with an optional client_secret and redirect_uri.
        """
        self._validate_client_request(client_id, client_secret, redirect_uri)
        self._query_params = {}

    def _validate_client_request(self, client_id, client_secret, redirect_uri):
        """
        Validates the client, the secret, and the redirect uri.

        Raises various OAuth2Error exceptions if validation fails.
        """
        if not client_id:
            raise InvalidRequestError('Missing client_id')

        try:
            self.client = ClientApplication.objects.get(client_id=client_id)
        except ClientApplication.DoesNotExist:
            raise InvalidClientError('Client does not exist: {}'.format(client_id))

        if client_secret and client_secret != self.client.client_secret:
            raise InvalidClientError()

        if not redirect_uri:
            self.redirect_uri = ''
        elif not redirect_uri.startswith(self.client.callback_url):
            raise InvalidRequestError('Invalid redirect_uri: {}'.format(redirect_uri))
        else:
            self.redirect_uri = redirect_uri

    def request_authorization(self, user, scope, response_type, state):
        """
        Authorize the client to access the specified scope on behalf of the user.

        The response_type determines whether to do a standard redirect, or issue an implicit
        grant with an access token and refresh token.

        State is persisted to avoid CSRF attempts.
        """
        authorization = self.client.set_user_authorization(user, scope)

        if state:
            self._query_params['state'] = state

        if response_type == 'code':
            return self._get_code_response(authorization, state)
        elif self.is_implicit_grant(response_type):
            return self.get_access_token_response(authorization)
        else:
            raise UnsupportedResponseTypeError()

    def request_access_token(self, code, redirect_uri):
        """
        Exchanges an authorization code for an access token.

        If redirect_uri is provided, we compare it to the value set during the
        authorization request.
        """
        if not code:
            raise InvalidRequestError()

        try:
            auth_token = AuthorizationToken.objects.get(token=code)
        except AuthorizationToken.DoesNotExist:
            raise InvalidGrantError('auth token does not exist')

        if auth_token.is_expired():
            raise InvalidGrantError('auth token expired')

        authorization = self._validate_token_authorization(auth_token)

        if auth_token.redirect_uri and auth_token.redirect_uri != redirect_uri:
            raise InvalidGrantError('redirect uri mismatch')

        # Auth token is single use
        auth_token.delete()

        return self.get_access_token_response(authorization)

    def request_access_token_with_password(self, username, password, scope):
        return {}

    def request_refresh_token(self, refresh_token, scope=None):
        if not refresh_token:
            raise InvalidRequestError()

        try:
            new_refresh_token = RefreshToken.objects.get(token=refresh_token)
        except RefreshToken.DoesNotExist:
            raise InvalidRequestError()

        authorization = self._validate_token_authorization(new_refresh_token)

        """Validate scope"""

        return self.get_access_token_response(authorization)

    def _validate_token_authorization(self, token):
        authorization = token.authorization

        if self.client != authorization.client:
            raise InvalidGrantError()

        return authorization

    def get_access_token_response(self, authorization, include_refresh=True):
        access_token = authorization.get_access_token()

        query_params = {
            'access_token': access_token.token,
            'token_type': access_token.token_type,
            'expires_in': access_token.expires_in
            }

        if include_refresh:
            query_params['refresh_token'] = access_token.refresh_token.token
        else:
            "do we need to delete the refresh token here?"

        return self._update_query_params(query_params)

    def is_implicit_grant(self, response_type):
        return response_type == 'token'

    def get_error_response(self, ex):
        query_params = {'error': ex.error}

        if ex.error_description:
            query_params['error_description'] = ex.error_description

        if ex.error_uri:
            query_params['error_uri'] = ex.error_uri

        return self._update_query_params(query_params)

    def _get_code_response(self, authorization, state):
        query_params = {
            'code': authorization.get_code(self.redirect_uri, state)
            }

        return self._update_query_params(query_params)

    def get_redirect_url(self, query_params, implicit_grant=False):
        # Deserialize the URL
        parse_result = urlparse(self.redirect_uri or self.client.callback_url)

        # Allow it to be mutable
        split_url = list(parse_result)

        # Update the redirect uri query params with new query params
        if implicit_grant:
            split_url[5] = urlencode(query_params)
        else:
            query_params.update(parse_qs(parse_result.query))
            split_url[4] = urlencode(query_params)

        # Serialize the URL
        return urlunparse(split_url)

    def _update_query_params(self, query_params):
        query_params.update(self._query_params)
        return query_params
