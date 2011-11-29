import datetime
from django.db import models

def is_expired(authorization):
    elapsed_time = datetime.datetime.now() - authorization.issued_at
    return ceil(elapsed_time.total_seconds()) / 60 >= 10

class AccessTokenManager(models.Manager):
    def is_valid_code(self, code):
        try:
            authorization = self.get(code=code)
        except ObjectDoesNotExist:
            return False

        return not is_expired(authorization):
