from django.http import HttpResponseBadRequest
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View
from dzen.django.http import HttpResponse, HttpResponseNotAuthorized
from oauth2.exceptions import *
from oauth2.provider import OAuth2Provider
from oauth2.views import OAuth2DispatchView, OAuth2ViewMixin
from urllib import urlencode

class TokenView(OAuth2ViewMixin, View):
    def post(self, request, *args, **kwargs):
        return self.handle_request(request, *args, **kwargs)

class AccessTokenView(TokenView):
    pass

class RefreshTokenView(TokenView):
    pass

class PasswordView(TokenView):
    pass

class TokenViewDispatcher(OAuth2DispatchView):
    dispatch_views = {
            'authorization_code': AccessTokenView,
            'refresh_token': RefreshTokenView,
            'password': PasswordView
            }

    @method_decorator(csrf_exempt)
    def dispatch(self, *args, **kwargs):
        return super(TokenViewDispatcher, self).dispatch(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        try:
            return self.dispatch_request(request, *args, **kwargs)
        except OAuth2Error, ex:
            response = self.provider.get_error_response(ex)
            return HttpResponseBadRequest(urlencode(response))

    def get_dispatch_key(self, request):
        try:
            return request.POST['grant_type']
        except KeyError:
            raise InvalidRequestError()

    def get_provider(self, request):
        client_id, client_secret = self.get_client_credentials(request)

        # TODO include basic auth
        return OAuth2Provider(
                client_id,
                client_secret,
                request.POST.get('redirect_uri', None)
                )

    def get_client_credentials(self, request):
        if hasattr(request, 'basic_auth'):
            return request.basic_auth

        try:
            return request.POST['client_id'], request.POST['client_secret']
        except KeyError:
            raise InvalidClientError()

    def handle_provider_error(self, request, ex):
        return HttpResponseNotAuthorized(request)

    def handle_dispatch_error(self, request, ex):
        if type(ex) is InvalidRequestError:
            raise ex

        raise UnsupportedGrantTypeError()
