from datetime import datetime, timedelta
from django.contrib.auth.models import User
from django.db import models
from oauth2_provider.managers import AccessTokenManager, AuthorizationTokenManager
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

    def save(self, *args, **kwargs):
        if not self.id:
            self.client_id = generate_token()
            self.client_secret = generate_token()

        super(ClientApplication, self).save(*args, **kwargs)

    def __unicode__(self):
        return self.name

class Authorization(models.Model):
    client = models.ForeignKey(ClientApplication)
    user = models.ForeignKey(User)
    scope = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ['client', 'user']
        unique_together = ('client', 'user')

    def __unicode__(self):
        return '{} authorizes {}'.format(self.user, self.client)

class Token(models.Model):
    authorization = models.ForeignKey(Authorization, unique=True)
    token = models.CharField(max_length=40, unique=True)

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

    def regenerate(self):
        if self.id or not self.expires_at:
            self.expires_at = datetime.now() + self.TTL

        super(ExpirableToken, self).regenerate()

class AuthorizationToken(ExpirableToken):
    TTL = timedelta(minutes=10)
    state = models.CharField(max_length=255, blank=True)
    redirect_uri = models.URLField(blank=True)

    objects = AuthorizationTokenManager()

class AccessToken(ExpirableToken):
    TTL = timedelta(hours=1)
    token_type = models.CharField(max_length=20, db_index=True)

    objects = AccessTokenManager()

class RefreshToken(Token):
    pass
