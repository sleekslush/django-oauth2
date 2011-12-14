from django.views.generic import View
from oauth2.exceptions import *

class OAuth2DispatchView(View):
    dispatch_views = {}

    def dispatch_request(self, request, *args, **kwargs):
        """
        Get the OAuth2 provider and look for the view that needs to get dispatched
        based on the key returned from self.get_dispatch_key

        Once the view is found, we construct and dispatch it, providing the provider
        as an argument to the view.
        """
        try:
            self.provider = self.get_provider(request)
        except Exception, ex:
            return self.handle_provider_error(request, ex)

        try:
            view_class = self.get_dispatch_view(request)
        except Exception, ex:
            return self.handle_dispatch_error(request, ex)

        view = view_class.as_view(provider=self.provider)

        return view(request, *args, **kwargs)

    def get_provider(self, request):
        """
        Returns an OAuth2 provider
        """
        raise NotImplementedError(self.get_provider)

    def handle_provider_error(self, request, ex):
        """
        Override this method to provide custom behavior if a provider could not be created
        """
        raise

    def get_dispatch_view(self, request):
        """
        Looks at the dispatch_views dict and selects the view as determined
        by the result of self.get_dispatch_key
        """
        return self.dispatch_views[self.get_dispatch_key(request)]

    def get_dispatch_key(self, request):
        """
        Based on the request, return the key of the view that we want to dispatch. Doesn't
        necessarily get called if you override self.get_dispatch_view and provide
        custom behavior.
        """
        raise NotImplementedError(self.get_dispatch_key)

    def handle_dispatch_error(self, request, ex):
        """
        Override this method to provide custom behavior if a view was not found
        """
        raise

class OAuth2ViewMixin(object):
    provider = None

    def dispatch_request(self, request, *args, **kwargs):
        try:
            return self.oauth2_request(request)
        except Exception, ex:
            # TODO log the error
            return self.get_error_response(ex)

    def oauth2_request(self, request):
        raise NotImplementedError(self.oauth2_request)

    def get_error_response(self, ex):
        raise
