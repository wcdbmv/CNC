from django.db import models

from webmail.managers import MessageManager


class Message(models.Model):
    from_email = models.CharField(max_length=254)
    time = models.DateTimeField()
    subject = models.TextField()
    body = models.TextField()

    objects = MessageManager()

    def get_to_emails(self):
        to_emails = []
        for recipient in self.recipient.all():
            to_emails.append(recipient.to_email)
        return to_emails


class MessageTo(models.Model):
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name='recipient')
    to_email = models.CharField(max_length=254)
