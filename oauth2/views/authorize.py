from django.views.generic import RedirectView, View
from dzen.django.apps.common.views import ProtectedViewMixin
from oauth2.exceptions import *
from oauth2.provider import OAuth2Provider
from oauth2.views import OAuth2DispatchMixin, OAuth2ViewMixin

class BaseAuthorizeView(ProtectedViewMixin, OAuth2ViewMixin, RedirectView):
    permanent = False

    def get(self, request, *args, **kwargs):
        self.handle_request(request, *args, **kwargs)
        return super(BaseAuthorizeView, self).get(request, *args, **kwargs)

class AuthorizeView(BaseAuthorizeView):
    def get_response(self, request):
        return self.provider.request_authorization(
                request.user,
                request.REQUEST.get('scope', ''),
                'code',
                request.REQUEST.get('state', '')
                )

    def handle_response(self, request, response, *args, **kwargs):
        self.url = self.provider.get_redirect_url(response)

class ImplicitAuthorizeView(BaseAuthorizeView):
    def get_response(self, request):
        return self.provider.request_authorization(
                request.user,
                request.REQUEST.get('scope', ''),
                'token',
                request.REQUEST.get('state', '')
                )

    def handle_response(self, request, response, *args, **kwargs):
        self.url = self.provider.get_redirect_url(response, True)

class AuthorizeViewDispatcher(OAuth2DispatchMixin, View):
    dispatch_views = {
            'code': AuthorizeView,
            'token': ImplicitAuthorizeView,
            }

    def get(self, request, *args, **kwargs):
        return self.dispatch_request(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.get(request, *args, **kwargs)

    def get_provider(self, request):
        return OAuth2Provider(
                request.REQUEST.get('client_id', None),
                request.REQUEST.get('redirect_uri', None)
                )

    def get_dispatch_key(self, request):
        return request.REQUEST.get('response_type', 'code')
