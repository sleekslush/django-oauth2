from django.conf.urls.defaults import patterns, include, url
from oauth2.views.authorize import AuthorizeViewDispatcher

urlpatterns = patterns('',
        url(r'^authorize/$', AuthorizeViewDispatcher.as_view(), name='authorize'),
        )
