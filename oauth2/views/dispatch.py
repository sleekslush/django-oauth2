from oauth2.views import OAuth2DispatchMixin

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
