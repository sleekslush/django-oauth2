from django.conf.urls.defaults import patterns, include, url
from oauth2_provider.views import *

urlpatterns = patterns('',
        url(r'^authorize/$', AuthorizeView.as_view(), name='authorize'),
        )
