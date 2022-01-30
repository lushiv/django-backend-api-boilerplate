from django import forms
from django.core.validators import RegexValidator

alphanumeric = RegexValidator(regex=r'^[0-9a-zA-Z]*$', message='Only alphanumeric characters are allowed.')

class PasswordForm(forms.Form):
    old_password=forms.CharField(label='old password',widget=forms.PasswordInput(),min_length=5,max_length=25,required=True)
    new_password = forms.CharField(label='new Password',widget=forms.PasswordInput(),min_length=5,max_length=25,required=True)
    email=forms.EmailField(label="email", max_length=45,required=True)