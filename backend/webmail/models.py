from django.db import models


class Message(models.Model):
    from_email = models.CharField(max_length=254)
    time = models.DateTimeField()
    subject = models.TextField()
    body = models.TextField()


class MessageTo(models.Model):
    message = models.ForeignKey(Message, on_delete=models.CASCADE)
    to_email = models.CharField(max_length=254)
