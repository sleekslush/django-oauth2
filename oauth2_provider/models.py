from django.contrib.auth.models import User
from django.db import models

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
    code = models.CharField(max_length=40, unique=True)
    redirection_uri = models.URLField()
    issued_at = models.DateTimeField(auto_now_add=True, db_index=True)
    scope = models.CharField(max_length=255)
    state = models.CharField(max_length=255)

    class Meta:
        unique_together = ('client', 'user')

    def __unicode__(self):
        return self.code

class Token(models.Model):
    client = models.ForeignKey(ClientApplication)
    user = models.ForeignKey(User)
    token = models.CharField(max_length=40, unique=True)
    scope = models.CharField(max_length=255)

    class Meta:
        abstract = True

    def __unicode__(self):
        return self.token

class AccessToken(Token):
    token_type = models.CharField(max_length=20, db_index=True)
    expires_at = models.DateTimeField(db_index=True)
    state = models.CharField(max_length=255)

class RefreshToken(Token):
    class Meta(Token.Meta):
        unique_together = ('client', 'user')
