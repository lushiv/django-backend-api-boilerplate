from django import forms
from django.core.validators import RegexValidator

class LoginForm(forms.Form):
    password = forms.CharField(label='Password',min_length=5,max_length=25,required=True)
    email=forms.EmailField(label="email", max_length=45,required=True)


class PasswordForm(forms.Form):
    old_password=forms.CharField(label='old password',widget=forms.PasswordInput(),min_length=5,max_length=30,required=True)
    new_password = forms.CharField(label='new Password',widget=forms.PasswordInput(),min_length=5,max_length=30,required=True)