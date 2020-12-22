from django import forms


class MessageForm(forms.Form):
    from_email = forms.CharField()
    to_emails = forms.CharField()
    subject = forms.CharField()
    body = forms.CharField()
