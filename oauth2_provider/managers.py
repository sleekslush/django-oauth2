import datetime
from django.db import models

class AccessTokenManager(models.Manager):
    def is_valid_code(self, code):
        try:
            authorization = self.get(code=code)
        except ObjectDoesNotExist:
            return False

        if self.is_expired(authorization):
            authorization.delete()
            return False

        return True

    def is_expired(self, authorization):
        elapsed_time = datetime.datetime.now() - authorization.issued_at
        return ceil(elapsed_time.total_seconds()) / 60 >= 10
