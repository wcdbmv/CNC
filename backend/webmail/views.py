from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.http import Http404
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.views.generic import ListView, CreateView, DetailView, DeleteView

from webmail.models import Message


class RegisterView(CreateView):
    model = User
    fields = ['username', 'email', 'password']
    template_name = 'webmail/register.html'
    success_url = reverse_lazy('webmail:inbox')

    def form_valid(self, form):
        form.instance.password = make_password(form.instance.password)
        valid = super().form_valid(form)
        user = form.save()
        login(self.request, user)
        return valid


@method_decorator(login_required, name='dispatch')
class InboxView(ListView):
    model = Message
    template_name = 'webmail/inbox.html'
    context_object_name = 'messages'

    def get_queryset(self):
        return Message.objects.get_inbox(self.request.user.email)


@method_decorator(login_required, name='dispatch')
class OutboxView(ListView):
    model = Message
    template_name = 'webmail/outbox.html'
    context_object_name = 'messages'

    def get_queryset(self):
        return Message.objects.get_outbox(self.request.user.email)


@method_decorator(login_required, name='dispatch')
class MessageDetailView(DetailView):
    model = Message
    template_name = 'webmail/message.html'
    context_object_name = 'message'
