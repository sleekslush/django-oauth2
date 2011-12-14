from django.http import HttpResponseBadRequest
from django.views.generic import View
from dzen.django.apps.common.views import CSRFExemptMixin, JSONResponseMixin
from dzen.django.http import HttpResponseNotAuthorized
from oauth2.exceptions import *
from oauth2.provider import OAuth2Provider
from oauth2.views import OAuth2DispatchView, OAuth2ViewMixin

class TokenView(OAuth2ViewMixin, View):
    def post(self, request, *args, **kwargs):
        return self.dispatch_request(request, *args, **kwargs)

class AccessTokenView(TokenView):
    grant_type = 'authorization_code'

    def oauth2_request(self, request):
        return self.provider.request_access_token(
                request.POST.get('code'),
                request.POST.get('redirect_uri')
                )

class RefreshTokenView(TokenView):
    grant_type = 'refresh_token'

    def oauth2_request(self, request):
        return self.provider.request_refresh_token(
                request.POST.get('refresh_token'),
                request.POST.get('scope')
                )

class PasswordView(TokenView):
    grant_type = 'password'

class TokenViewDispatcher(CSRFExemptMixin, JSONResponseMixin, OAuth2DispatchView):
    dispatch_views = {
            AccessTokenView.grant_type: AccessTokenView,
            RefreshTokenView.grant_type: RefreshTokenView,
            PasswordView.grant_type: PasswordView
            }

    def post(self, request, *args, **kwargs):
        try:
            return self.render_to_response(self.dispatch_request(request, *args, **kwargs))
        except OAuth2Error, ex:
            response = self.provider.get_error_response(ex)
            return HttpResponseBadRequest(self.render_to_response(response))

    def get_dispatch_key(self, request):
        try:
            return request.POST['grant_type']
        except KeyError:
            raise InvalidRequestError('Missing grant type')

    def get_provider(self, request):
        client_id, client_secret = self.get_client_credentials(request)

        return OAuth2Provider(
                client_id,
                client_secret,
                request.POST.get('redirect_uri')
                )

    def get_client_credentials(self, request):
        if hasattr(request, 'basic_auth'):
            return request.basic_auth

        try:
            return request.POST['client_id'], request.POST['client_secret']
        except KeyError:
            raise InvalidClientError('Invalid client')

    def handle_provider_error(self, request, ex):
        return HttpResponseNotAuthorized(request, ex.message)

    def handle_dispatch_error(self, request, ex):
        if type(ex) is InvalidRequestError:
            raise ex

        raise UnsupportedGrantTypeError('Unsupported grant type')
