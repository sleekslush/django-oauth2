from django.db import models

class DefaultManager(models.Manager):
    def update_or_create(self, save=True, **kwargs):
        defaults = kwargs.get('defaults', {})
        model, created = self.get_or_create(**kwargs)
        
        if not created and defaults:
            for key in defaults:
                setattr(model, key, defaults[key])

            save and model.save()

        return model, created

class AuthorizationManager(DefaultManager):
    pass

class TokenManager(DefaultManager):
    def regenerate(self, **kwargs):
        token, created = self.update_or_create(False, **kwargs)
        
        if not created:
            token.regenerate()
            token.save()

        return token
