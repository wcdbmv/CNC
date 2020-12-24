from django.db import models

from webmail.managers import MessageManager


class Message(models.Model):
    from_email = models.CharField(max_length=254)
    to_emails = models.TextField()
    time = models.DateTimeField()
    subject = models.TextField()
    body = models.TextField()

    objects = MessageManager()

    def get_to_emails(self):
        return self.to_emails.split()


class MessageTo(models.Model):
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name='recipient')
    to_email = models.CharField(max_length=254)


class MessageFrom(models.Model):
    message = models.ForeignKey(Message, on_delete=models.CASCADE, related_name='sender')
    from_email = models.CharField(max_length=254)
