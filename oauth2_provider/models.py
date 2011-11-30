import uuid
from django.contrib.auth.models import User
from django.db import models
from oauth2_provider.managers import AccessTokenManager, AuthorizationTokenManager

class ClientApplication(models.Model):
    client_id = models.CharField(max_length=40, unique=True)
    client_secret = models.CharField(max_length=40, unique=True)
    name = models.CharField(max_length=255)
    website_url = models.URLField()
    callback_url = models.URLField()
    description = models.TextField()

    def __unicode__(self):
        return self.name

class Authorization(models.Model):
    client = models.ForeignKey(ClientApplication)
    user = models.ForeignKey(User)
    scope = models.CharField(max_length=255)

    class Meta:
        unique_together = ('client', 'user')

    def __unicode__(self):
        return self.code

class Token(models.Model):
    authorization = models.ForeignKey(Authorization, unique=True)
    token = models.CharField(max_length=40, unique=True)

    class Meta:
        abstract = True

    def regenerate(self):
        self.token = uuid.uuid4().hex

    def save(self, *args, **kwargs):
        if not self.id:
            self.regenerate()

        super(Token, self).save(*args, **kwargs)

    def __unicode__(self):
        return self.token

class ExpirableToken(Token):
    expires_at = models.DateTimeField(db_index=True)

    class Meta(Token.Meta):
        pass

class AuthorizationToken(ExpirableToken):
    state = models.CharField(max_length=255)
    redirect_uri = models.URLField()

    objects = AuthorizationTokenManager()

class AccessToken(ExpirableToken):
    token_type = models.CharField(max_length=20, db_index=True)

    objects = AccessTokenManager()

class RefreshToken(Token):
    pass
