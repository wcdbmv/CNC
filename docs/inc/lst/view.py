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
