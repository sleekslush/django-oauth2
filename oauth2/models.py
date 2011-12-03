import math
from datetime import datetime, timedelta
from django.contrib.auth.models import User
from django.db import models
from oauth2.exceptions import InvalidGrantError
from oauth2.managers import TokenManager
from uuid import uuid4

def generate_token():
    return uuid4().hex

class ClientApplication(models.Model):
    client_id = models.CharField(max_length=40, unique=True)
    client_secret = models.CharField(max_length=40, unique=True)
    name = models.CharField(max_length=255)
    website_url = models.URLField()
    callback_url = models.URLField()
    description = models.TextField(blank=True)

    class Meta:
        ordering = ['name']

    def set_user_authorization(self, user, scope=''):
        authorization, created = self.authorization_set.get_or_create(user=user)

        if not created:
            authorization.scope = scope
            authorization.save()

        return authorization

    def save(self, *args, **kwargs):
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

    class Meta:
        ordering = ['client', 'user']
        unique_together = ('client', 'user')

    def get_code(self, redirect_uri, state):
        auth_token, created = self.authorizationtoken_set.regenerate()
        auth_token.redirect_uri = redirect_uri
        auth_token.state = state
        auth_token.save()

        return auth_token

    def get_access_token(self, token_type='example', auth_token=None):
        if auth_token:
            if auth_token.is_expired():
                raise InvalidGrantError()

            auth_token.delete()

        access_token, created = self.accesstoken_set.regenerate()
        access_token.token_type = token_type
        access_token.save()

        return access_token

    def refresh_access_token(self, refresh_token, token_type='example'):
        refresh_token.delete()
        return self.get_access_token(token_type)

    def __unicode__(self):
        return '{} authorizes {}'.format(self.user, self.client)

class Token(models.Model):
    authorization = models.ForeignKey(Authorization, unique=True)
    token = models.CharField(max_length=40, unique=True)

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
        refresh_token, created = self.authorization.refreshtoken_set.regenerate(True)
        return refresh_token

class RefreshToken(Token):
    pass
