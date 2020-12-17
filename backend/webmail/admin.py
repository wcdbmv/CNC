from django.contrib import admin

from webmail.models import Message, MessageTo

admin.site.register(Message)
admin.site.register(MessageTo)
