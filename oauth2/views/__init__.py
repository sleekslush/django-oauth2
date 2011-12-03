from django.http import HttpResponse
from oauth2.exceptions import *

class OAuth2ViewMixin(object):
    provider = None

    def handle_request(self, request, *args, **kwargs):
        try:
            response = self.get_response(request)
        except OAuth2Error, ex:
            response = self.get_error_response(ex)
        except Exception, ex:
            # TODO log the error
            response = self.get_error_response(ex)

        return self.handle_response(request, response, *args, **kwargs)

    def get_response(self, request):
        raise NotImplementedError(self.get_response)

    def get_error_response(self, ex):
        raise

    def handle_provider_error(self, ex):
        return HttpResponse(ex.message)

    def handle_error_response(self, ex):
        raise NotImplementedError(self.handle_error_response)

    def handle_response(self, request, response, *args, **kwargs):
        raise NotImplementedError(self.handle_response)

class OAuth2DispatchMixin(object):
    dispatch_views = {}

    def dispatch_request(self, request, *args, **kwargs):
        try:
            provider = self.get_provider(request)
        except Exception, ex:
            return self.handle_provider_error(ex)

        try:
            view_class = self.dispatch_views[self.get_dispatch_key(request)]
        except KeyError, ex:
            return self.handle_dispatch_error(request, ex)

        return view_class.as_view(provider=provider)(request, *args, **kwargs)

    def get_provider(self, request):
        raise NotImplementedError(self.get_provider)

    def handle_provider_error(self, ex):
        raise

    def get_dispatch_key(self, request):
        raise NotImplementedError(self.get_dispatch_key)

    def handle_dispatch_error(self, request, ex):
        raise NotImplementedError(self.handle_dispatch_error)
