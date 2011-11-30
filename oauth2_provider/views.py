import urllib
from django.http import HttpResponse
from django.views.generic import RedirectView
from dzen.django.apps.common.views import ProtectedViewMixin
from oauth2_provider.exceptions import *
from oauth2_provider.models import Client
from urlparse import urlparse, urlunparse

class OAuth2RedirectView(RedirectView):
    permanent = False
    fragment = False
    query_params = {}

    def get_redirect_url(self, **kwargs):
        # Deserialize the URL
        parse_result = urlparse.urlparse(self.url)

        # Allow it to be mutable
        split_url = list(parse_result)

        # Update the redirect uri query params with new query params
        if self.fragment:
            split_url[5] = urllib.urlencode(self.query_params)
        else:
            query_params = urllib2.parse_qs(parse_result.query)
            query_params.update(self.query_params)
            split_url[4] = urllib.urlencode(query_params)

        # Serialize the URL
        url = urlparse.urlunparse(split_url)

        return url % kwargs

    def _get_error_query_params(self, ex):
        query_params = {'error': ex.error}

        if ex.error_description:
            query_params['error_description'] = ex.error_description

        if ex.error_uri:
            query_params['error_uri'] = ex.error_uri

        if ex.state:
            query_params['state'] = ex.state

        return query_params

class AuthorizeView(ProtectedViewMixin, OAuth2RedirectView):
    def get(self, request, *args, **kwargs):
        try:
            client = self._get_client(request)
            redirect_uri = self._get_redirect_uri(request, client)
        except (InvalidClientError, InvalidRedirectError), ex:
            return HttpResponse(ex.message)

        try:
            response_type = self._get_response_type(request)
            scope = request.GET.get('scope', None)
            state = request.GET.get('state', None)
        except OAuth2Error, ex:
            self.query_params = self._get_error_query_params(ex)
        except Exception, ex:
            # TODO log the error
            self.query_params = self._get_error_query_params(ServerError())
        else:
            self.query_params = self._generate_authorization_token(
                    client, request.user, redirect_uri, scope, state)

        self.url = redirect_uri

        return super(AuthorizeView, self).get(request, *args, **kwargs)

    def _get_client(self, request):
        try:
            client_id = request.GET['client_id']
        except KeyError:
            raise InvalidRequestError('Missing client_id')

        try:
            return Client.objects.get(client_id=client_id)
        except Client.DoesNotExist:
            raise InvalidClientError('Client does not exist: {}'.format(client_id))

    def _get_redirect_uri(self, request, client):
        try:
            redirect_uri = request.GET['redirect_uri']
        except KeyError:
            return client.callback_url

        if not redirect_uri.startswith(client.callback_url):
            raise InvalidRedirectUriError('Invalid redirect_uri: {}'.format(redirect_uri))

        return redirect_uri

    def _get_response_type(self, request):
        response_type = request.GET.get('response_type', 'code')

        if response_type not in ('code', 'token'):
            raise UnsupportedResponseType()

        self.fragment = response_type is 'token'

        return response_type

   def _generate_authorization_token(self, client, user, redirect_uri, scope, state):
       authorization = self._get_authorization(client, user, scope)
       return self._get_token(authorization, redirect_uri, state)

   def _get_authorization(self, client, user, scope):
       authorization, created = client.authorization_set.get_or_create(user=user, scope=scope)

       if not created:
           # TODO check if scope is ok here
           authorization.scope = scope
           authorization.save()

       return authorization

   def _get_token(self, authorization, redirect_uri, state):
       token, created = authorization.authorizationtoken_set.get_or_create(
               redirection_uri=redirect_uri, state=state)

       if not created:
           token.regenerate()
           token.save()

       return token
