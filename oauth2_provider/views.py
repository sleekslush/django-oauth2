import urllib
from django.http import HttpResponse
from django.views.generic import RedirectView
from dzen.django.apps.common.views import ProtectedViewMixin
from oauth2_provider.exceptions import *
from oauth2_provider.models import ClientApplication
from urlparse import parse_qs, urlparse, urlunparse

class AuthorizeView(ProtectedViewMixin, RedirectView):
    permanent = False

    def dispatch(self, request, *args, **kwargs):
        self.implicit_grant = False
        self.query_params = {}
        return super(RedirectView, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        try:
            client = self._get_client(request)
            redirect_uri = self._get_redirect_uri(request, client)
        except (InvalidClientError, InvalidRequestError), ex:
            return HttpResponse(ex.message)

        try:
            self._determine_response_type(request)
            state = self._get_state(request)
            scope = request.REQUEST.get('scope', '')

            # authorize the client access to this user
            authorization = client.set_user_authorization(request.user, scope)

            if self.implicit_grant:
                access_token = authorization.get_access_token()
                response = {
                        'access_token': access_token.token,
                        'token_type': access_token.token_type,
                        'expires_in': access_token.get_expires_in(),
                        'refresh_token': access_token.get_refresh_token()
                        }
            else:
                response = {'code': authorization.get_code(redirect_uri, state)}
        except OAuth2Error, ex:
            self.query_params.update(self._get_error_query_params(ex))
        except Exception, ex:
            # TODO log the error
            raise
            self.query_params.update(self._get_error_query_params(ServerError()))
        else:
            self.query_params.update(response)

        self.url = redirect_uri

        return super(AuthorizeView, self).get(request, *args, **kwargs)

    def get_redirect_url(self, **kwargs):
        # Deserialize the URL
        parse_result = urlparse(self.url)

        # Allow it to be mutable
        split_url = list(parse_result)

        # Update the redirect uri query params with new query params
        if self.implicit_grant:
            split_url[5] = urllib.urlencode(self.query_params)
        else:
            query_params = parse_qs(parse_result.query)
            query_params.update(self.query_params)
            split_url[4] = urllib.urlencode(query_params)

        # Serialize the URL
        url = urlunparse(split_url)

        return url % kwargs

    def _get_client(self, request):
        try:
            client_id = request.REQUEST['client_id']
        except KeyError:
            raise InvalidRequestError('Missing client_id')

        try:
            return ClientApplication.objects.get(client_id=client_id)
        except ClientApplication.DoesNotExist:
            raise InvalidClientError('Client does not exist: {}'.format(client_id))

    def _get_redirect_uri(self, request, client):
        try:
            redirect_uri = request.REQUEST['redirect_uri']
        except KeyError:
            return client.callback_url

        if not redirect_uri.startswith(client.callback_url):
            raise InvalidRequestError('Invalid redirect_uri: {}'.format(redirect_uri))

        return redirect_uri

    def _get_state(self, request):
        state = request.REQUEST.get('state', '')

        if state:
            self.query_params['state'] = state

        return state

    def _determine_response_type(self, request):
        response_type = request.REQUEST.get('response_type', 'code')

        if response_type not in ('code', 'token'):
            raise UnsupportedResponseTypeError()

        self.implicit_grant = (response_type == 'token')

    def _get_error_query_params(self, ex):
        query_params = {'error': ex.error}

        if ex.error_description:
            query_params['error_description'] = ex.error_description

        if ex.error_uri:
            query_params['error_uri'] = ex.error_uri

        if ex.state:
            query_params['state'] = ex.state

        return query_params
