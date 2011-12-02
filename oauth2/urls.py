from django.conf.urls.defaults import patterns, include, url
from oauth2.views import *

urlpatterns = patterns('',
        url(r'^authorize/$', AuthorizeView.as_view(), name='authorize'),
        )
