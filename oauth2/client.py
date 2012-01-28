import json
import requests
from urllib import urlencode
from urlparse import urljoin

class OAuth2Client(object):
    def __init__(self, client_id, client_secret, base_url, use_basic_auth=True):
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url if base_url.endswith('/') else base_url + '/'
        self.use_basic_auth = use_basic_auth

    def get_authorization_url(self, redirect_uri=None, scope=None, state=None, implicit_grant=False, path='authorize'):
        query_params = self._strip_dict({
            'response_type': 'code' if not implicit_grant else 'token',
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'scope': scope,
            'state': state
            })

        return '{}?{}'.format(self._get_endpoint(path), urlencode(query_params))

    def get_access_token(self, code, redirect_uri=None, path='token'):
        post_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri
            }

        return self._post_request(path, post_data)

    def get_access_token_for_owner(self, username, password, scope=None, path='token'):
        post_data = {
            'grant_type': 'password',
            'username': username,
            'password': password,
            'scope': scope
            }

        return self._post_request(path, post_data)

    def get_access_token_for_client(self, scope=None, path='token'):
        post_data = {
            'grant_type': 'client_credentials',
            'scope': scope
            }

        return self._post_request(path, post_data)

    def refresh_access_token(self, refresh_token, scope=None, path='token'):
        post_data = {
            'grant_type': 'refresh_token',
            'scope': scope
            }

        return self._post_request(path, post_data)

    def _post_request(self, path, data):
        response = requests.post(self._get_endpoint(path), data=self._strip_dict(data),
                auth=(self.client_id, self.client_secret) if self.use_basic_auth else None)

        return json.loads(response.text)

    def _strip_dict(self, d):
        return dict((key, value) for key, value in d.iteritems() if value not in ('', None))

    def _get_endpoint(self, path):
        return urljoin(self.base_url, path)
