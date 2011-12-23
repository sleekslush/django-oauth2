import math
from datetime import datetime, timedelta
from django.contrib.auth.models import User
from django.core import serializers
from django.db import models
from oauth2.exceptions import InvalidGrantError
from oauth2.managers import AuthorizationManager, TokenManager
from uuid import uuid4

def generate_token():
    return uuid4().hex

class ClientApplication(models.Model):
    """
    Represents a client that has been granted the ability to access the OAuth2 provider.
    """
    client_id = models.CharField(max_length=40, unique=True)
    client_secret = models.CharField(max_length=40, unique=True, serialize=False)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    is_trusted = models.BooleanField(default=False)
    name = models.CharField(max_length=255)
    website_url = models.URLField()
    callback_url = models.URLField()
    description = models.TextField(blank=True)

    class Meta:
        ordering = ['-created_at', 'name']

    def set_user_authorization(self, user, scope=''):
        """
        Grants the client access to the provided user under the specified scope and
        returns the authorization model.
        """
        authorization, created = self.authorization_set.get_or_create(
                user=user,
                defaults={'scope': scope}
                )

        return authorization

    def save(self, *args, **kwargs):
        """
        Automagically assigns newly generated tokens to client_id and client_secret
        if this is the first time the object is getting saved.
        """
        if not self.id:
            self.client_id = generate_token()
            self.client_secret = generate_token()

        super(ClientApplication, self).save(*args, **kwargs)

    def __unicode__(self):
        return self.name

class Authorization(models.Model):
    client = models.ForeignKey(ClientApplication)
    user = models.ForeignKey(User, null=True)
    scope = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now=True, db_index=True)

    objects = AuthorizationManager()

    class Meta:
        ordering = ['client', 'user']
        unique_together = ('client', 'user')

    def get_code(self, redirect_uri, state):
        defaults = {
                'redirect_uri': redirect_uri,
                'state': state
                }

        return self.authorizationtoken_set.regenerate(defaults=defaults)

    def get_access_token(self, token_type='example', auth_token=None):
        if auth_token:
            if auth_token.is_expired():
                raise InvalidGrantError()

            auth_token.delete()

        return self.accesstoken_set.regenerate(defaults={'token_type': token_type})

    def refresh_access_token(self, refresh_token, token_type='example'):
        refresh_token.delete()
        return self.get_access_token(token_type)

    def __unicode__(self):
        return '{} authorizes {}'.format(self.user, self.client)

class Token(models.Model):
    authorization = models.ForeignKey(Authorization, unique=True)
    token = models.CharField(max_length=40, unique=True)
    #issued_at = models.DateTimeField(auto_now=True, db_index=True)

    objects = TokenManager()

    class Meta:
        abstract = True
        ordering = ['authorization']

    def regenerate(self):
        self.token = generate_token()

    def save(self, *args, **kwargs):
        if not self.id:
            self.regenerate()

        super(Token, self).save(*args, **kwargs)

    def __unicode__(self):
        return self.token

class ExpirableToken(Token):
    expires_at = models.DateTimeField(db_index=True)

    class Meta(Token.Meta):
        abstract = True
        ordering = ['authorization', '-expires_at']

    def is_expired(self):
        return self.get_expires_in == 0

    def get_expires_in(self):
        delta = self.expires_at - datetime.now()
        seconds = int(math.ceil(delta.total_seconds()))
        return seconds if seconds > 0 else 0

    def regenerate(self):
        if self.id or not self.expires_at:
            self.expires_at = datetime.now() + self.TTL

        super(ExpirableToken, self).regenerate()

class AuthorizationToken(ExpirableToken):
    TTL = timedelta(minutes=10)
    state = models.CharField(max_length=255, blank=True)
    redirect_uri = models.URLField(blank=True)

class AccessToken(ExpirableToken):
    TTL = timedelta(hours=1)
    token_type = models.CharField(max_length=20, db_index=True)

    def get_refresh_token(self):
        return self.authorization.refreshtoken_set.regenerate()

class RefreshToken(Token):
    pass
