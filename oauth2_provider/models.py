from django.contrib.auth.models import User
from django.db import models

class ClientApplication(models.Model):
    client_id = models.CharField(max_length=40)
    client_secret = models.CharField(max_length=40)
    name = models.CharField(max_length=255)
    website_url = models.URLField()
    callback_url = models.URLField()
    description = models.TextField()

    def __unicode__(self):
        return self.name

class Authorization(models.Model):
    user = models.ForeignKey(User)
    code = models.CharField(max_length=40, db_index=True, unique=True)
    client = models.ForeignKey(ClientApplication)
    redirection_uri = models.URLField()
    issued_at = models.DateTimeField(auto_now_add=True)
    scope = models.CharField(max_length=255)

class Token(models.Model):
    client = models.ForeignKey(ClientApplication)
    user = models.ForeignKey(User)
    token = models.CharField(max_length=40, db_index=True, unique=True)
    scope = models.CharField(max_length=255)

    class Meta:
        abstract = True

class AccessToken(Token):
    expires_at = models.DateTimeField()
    token_type = models.CharField(max_length=20)

class RefreshToken(Token):
    """
    The refresh token.
    """
