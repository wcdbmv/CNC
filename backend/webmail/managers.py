from django.db import models


class MessageManager(models.Manager):
    def get_inbox(self, email):
        return self.filter(recipient__to_email=email)

    def get_outbox(self, email):
        return self.filter(from_email=email)
