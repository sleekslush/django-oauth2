from django import forms
from oauth2.models import ClientApplication

class ClientApplicationForm(forms.ModelForm):
    class Meta:
        model = ClientApplication
