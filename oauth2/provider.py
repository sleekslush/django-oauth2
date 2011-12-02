from oauth2.exceptions import *
from oauth2.models import ClientApplication
from urllib import urlencode
from urlparse import parse_qs, urlparse, urlunparse

class OAuth2Provider(object):
    def __init__(self, client_id, redirect_uri=None):
        self._validate_client_request(client_id, redirect_uri)
        self._query_params = {}

    def _validate_client_request(self, client_id, redirect_uri):
        if not client_id:
            raise InvalidRequestError('Missing client_id')

        try:
            self.client = ClientApplication.objects.get(client_id=client_id)
        except ClientApplication.DoesNotExist:
            raise InvalidClientError('Client does not exist: {}'.format(client_id))

        if not redirect_uri:
            self.redirect_uri = self.client.callback_url
        elif not redirect_uri.startswitch(self.client.callback_url):
            raise InvalidRequestError('Invalid redirect_uri: {}'.format(redirect_uri))
        else:
            self.redirect_uri = redirect_uri

    def request_authorization(self, user, scope, response_type, state):
        authorization = self.client.set_user_authorization(user, scope)

        if state:
            self._query_params['state'] = state

        if response_type == 'code':
            return self._get_code_response(authorization, state)
        elif self.implicit_grant(response_type):
            return self.get_access_token_response(authorization)
        else:
            raise UnsupportedResponseTypeError()

    def implicit_grant(self, response_type):
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

    def get_access_token_response(self, authorization, include_refresh=True):
        access_token = authorization.get_access_token()

        query_params = {
            'access_token': access_token.token,
            'token_type': access_token.token_type,
            'expires_in': access_token.get_expires_in()
            }

        if include_refresh:
            query_params['refresh_token'] = access_token.get_refresh_token()
        else:
            "do we need to delete the refresh token here?"

        return self._update_query_params(query_params)

    def get_redirect_url(self, query_params, implicit_grant=False):
        # Deserialize the URL
        parse_result = urlparse(self.redirect_uri)

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
