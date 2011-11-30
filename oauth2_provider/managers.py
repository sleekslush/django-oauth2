from datetime import datetime
from django.db import models

class TokenManager(models.Manager):
    def is_expired(self, token):
        try:
            auth_token = self.get(token=token)
        except self.model.DoesNotExist:
            return True

        return auth_token.expires_at < datetime.now()

class AuthorizationTokenManager(TokenManager):
    pass

class AccessTokenManager(TokenManager):
    pass
