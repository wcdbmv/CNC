import re

from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.http import Http404
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.views.generic import ListView, CreateView, DetailView, DeleteView

from webmail.forms import MessageForm
from webmail.models import Message

from smtp_client import SmtpClient

SMTP_SERVER = ('0.0.0.0', 4467)
EMAIL_REGEX = r'[^@]+@mail.com$'


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

    def get_object(self, *args, **kwargs):
        entity = super().get_object(*args, **kwargs)
        if self.request.user.email not in entity.get_to_emails() + [entity.from_email]:
            raise Http404
        return entity


@method_decorator(login_required, name='dispatch')
class MessageDeleteView(DeleteView):
    model = Message

    def get_success_url(self):
        view_name = self.request.POST.get('view_name', 'webmail:inbox')
        return reverse_lazy(view_name)

    def get_object(self, *args, **kwargs):
        entity = super().get_object(*args, **kwargs)
        if self.request.user.email not in entity.get_to_emails() + [entity.from_email]:
            raise Http404
        return entity


def send_email(request):
    if request.method == 'POST':
        form = MessageForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            from_email = data['from_email']
            to_emails = data['to_emails'].split(' ')
            for email in to_emails:
                if not re.match(EMAIL_REGEX, email):
                    raise Http404
            msg = f'Subject: {data["subject"]}\n\n{data["body"]}'

            server = SmtpClient(*SMTP_SERVER)
            server.sendmail(from_email, to_emails, msg)
            server.quit()
        return redirect('webmail:outbox')
