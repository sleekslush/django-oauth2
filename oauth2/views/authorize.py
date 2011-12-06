from django.http import HttpResponseBadRequest
from django.views.generic import RedirectView
from dzen.django.apps.common.views import ProtectedViewMixin
from oauth2.exceptions import *
from oauth2.provider import OAuth2Provider
from oauth2.views import OAuth2DispatchView, OAuth2ViewMixin

class AuthorizeView(ProtectedViewMixin, OAuth2ViewMixin, RedirectView):
    permanent = False
    response_type = 'code'

    def get(self, request, *args, **kwargs):
        self.handle_request(request, *args, **kwargs)
        return super(AuthorizeView, self).get(request, *args, **kwargs)

    def get_response(self, request):
        return self.provider.request_authorization(
                request.user,
                request.REQUEST.get('scope', ''),
                self.response_type,
                request.REQUEST.get('state', '')
                )

    def handle_response(self, request, response, *args, **kwargs):
        self.url = self.provider.get_redirect_url(response, getattr(self, 'implicit_grant', False))

class ImplicitAuthorizeView(AuthorizeView):
    response_type = 'token'
    implicit_grant = True

class AuthorizeViewDispatcher(OAuth2DispatchView):
    dispatch_views = {
            AuthorizeView.response_type: AuthorizeView,
            ImplicitAuthorizeView.response_type: ImplicitAuthorizeView,
            }

    def get(self, request, *args, **kwargs):
        return self.dispatch_request(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        return self.get(request, *args, **kwargs)

    def get_provider(self, request):
        return OAuth2Provider(
                request.REQUEST.get('client_id'),
                redirect_uri=request.REQUEST.get('redirect_uri')
                )

    def handle_provider_error(self, request, ex):
        if not isinstance(ex, OAuth2Error):
            raise

        return HttpResponseBadRequest(ex.message)

    def get_dispatch_key(self, request):
        return request.REQUEST.get('response_type', 'code')
