from django.http import HttpResponse
from django.views.generic import RedirectView
from dzen.django.apps.common.views import ProtectedViewMixin
from oauth2.exceptions import *
from oauth2.provider import OAuth2Provider

class AuthorizeView(ProtectedViewMixin, RedirectView):
    permanent = False

    def dispatch(self, request, *args, **kwargs):
        self.implicit_grant = False
        self.query_params = {}
        return super(RedirectView, self).dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        try:
            oauth2_provider = OAuth2Provider(
                    request.REQUEST.get('client_id', None),
                    request.REQUEST.get('redirect_uri', None)
                    )
        except (InvalidClientError, InvalidRequestError), ex:
            return HttpResponse(ex.message)

        try:
            response_type = request.REQUEST.get('response_type', 'code')

            response = oauth2_provider.request_authorization(
                    request.user,
                    request.REQUEST.get('scope', ''),
                    response_type,
                    request.REQUEST.get('state', '')
                    )
        except OAuth2Error, ex:
            response = oauth2_provider.get_error_response(ex)
        except Exception, ex:
            # TODO log the error
            raise
            response = oauth2_provider.get_error_response(ServerError())

        self.url = oauth2_provider.get_redirect_url(
                response,
                oauth2_provider.implicit_grant(response_type)
                )

        return super(AuthorizeView, self).get(request, *args, **kwargs)
