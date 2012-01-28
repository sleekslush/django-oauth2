import json
import requests
from urllib import urlencode
from urlparse import urljoin

class OAuth2Client(object):
    def __init__(self, client_id, client_secret, base_url, use_basic_auth=True):
        """
        Constructs a new OAuth2 client wired up with the client credentials and base url
        for the auth endpoints.
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = base_url if base_url.endswith('/') else base_url + '/'
        self.use_basic_auth = use_basic_auth

    def get_authorization_url(self, redirect_uri=None, scope=None, state=None, implicit_grant=False, path='authorize'):
        """
        Returns the URL that you should send the user to in order to obtain an authorization code.

        redirect_uri The URL that the authorization server will redirect to once the user either accepts or denies
        scope The scope of resources the application is requesting access to
        state A value that should be used to prevent CSRF
        implicit_grant True if the implicit grant type flow should be used (hash fragment access token response)
        path The endpoint on the server relative to self.base_url
        """
        query_params = self._strip_dict({
            'response_type': 'code' if not implicit_grant else 'token',
            'client_id': self.client_id,
            'redirect_uri': redirect_uri,
            'scope': scope,
            'state': state
            })

        return '{}?{}'.format(self._get_endpoint(path), urlencode(query_params))

    def get_access_token(self, code, redirect_uri=None, path='token'):
        """
        POSTs an access token request to the authorization server and returns a JSON object.

        code The authorization code
        redirect_uri Must match the redirect_uri used to construct the initial authorization URL request
        path The endpoint on the server relative to self.base_url
        """
        post_data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri
            }

        return self._post_request(path, post_data)

    def get_access_token_for_owner(self, username, password, scope=None, path='token'):
        """
        POSTs an access token request to the authorization server using the owner's credentials
        instead of the authorization code and returns a JSON object.

        username The resource owner's username
        password The resource owner's password
        scope The scope of resources the application is requesting access to
        path The endpoint on the server relative to self.base_url
        """
        post_data = {
            'grant_type': 'password',
            'username': username,
            'password': password,
            'scope': scope
            }

        return self._post_request(path, post_data)

    def get_access_token_for_client(self, scope=None, path='token'):
        """
        POSTs an access token request to the authorization server using only client credentials
        instead of the authorization code and returns a JSON object.

        scope The scope of resources the application is requesting access to
        path The endpoint on the server relative to self.base_url
        """
        post_data = {
            'grant_type': 'client_credentials',
            'scope': scope
            }

        return self._post_request(path, post_data)

    def refresh_access_token(self, refresh_token, scope=None, path='token'):
        """
        POSTs a refresh token request to the authorization server using an already acquired
        refresh token. Returns a JSON object containing a new access token and optional refresh
        token.

        scope The scope of resources the application is requesting access to
        path The endpoint on the server relative to self.base_url
        """
        post_data = {
            'grant_type': 'refresh_token',
            'scope': scope
            }

        return self._post_request(path, post_data)

    def _post_request(self, path, data):
        """
        Sends POST requests to the authorization server. Handles client application authentication
        using Basic Auth or POST parameters depending on how the object was constructed with the
        `use_basic_auth` parameter. Returns a JSON decoded object from the response.
        """
        if self.use_basic_auth:
            auth = (self.client_id, self.client_secret)
        else:
            auth = None
            post_data.update({
                'client_id': self.client_id,
                'client_secret': self.client_secret
                })

        response = requests.post(self._get_endpoint(path), data=self._strip_dict(data), auth=auth)

        return json.loads(response.text)

    def _strip_dict(self, d):
        """
        Returns a dictionary that contains all key, value pairs from d that have a value that is non-empty
        and not None.
        """
        return dict((key, value) for key, value in d.iteritems() if value not in ('', None))

    def _get_endpoint(self, path):
        """
        Cleanly construct the authorization endpoint and return the resulting URL.
        """
        return urljoin(self.base_url, path)
