from django import forms
from oauth2.models import ClientApplication

class ClientApplicationForm(forms.ModelForm):
    class Meta:
        model = ClientApplication
        fields = ('name', 'website_url', 'callback_url', 'description',)
