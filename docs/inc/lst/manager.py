class MessageManager(models.Manager):
    def get_inbox(self, email):
        return self.filter(recipient__to_email=email).order_by('-time')

    def get_outbox(self, email):
        return self.filter(from_email=email).order_by('-time')
