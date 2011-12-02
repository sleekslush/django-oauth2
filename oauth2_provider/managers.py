from django.db import models

class TokenManager(models.Manager):
    def regenerate(self, save=False, **kwargs):
        token, created = self.get_or_create(**kwargs)
        
        if not created:
            token.regenerate()
            save and token.save()

        return token, created
