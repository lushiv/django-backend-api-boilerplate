from django import forms
from django.core.validators import RegexValidator

alphanumeric = RegexValidator(regex=r'^[0-9a-zA-Z]*$', message='Only alphanumeric characters are allowed.')

class KYCForm(forms.Form):
    first_name = forms.CharField(label='first name', max_length=45,required=True)
    last_name = forms.CharField(label='last name', max_length=45,required=True)
    gender = forms.CharField(label='gender', max_length=6,required=True)
    dob=forms.DateField(label='DOB',required=True)
    username=forms.CharField(label="username", max_length=45,required=True)
    email=forms.EmailField(label="email",required=True,max_length=50)
    address1=forms.CharField(label='address1', max_length=50,required=True)
    address2=forms.CharField(label='address2', max_length=50)
    city=forms.CharField(label="city", max_length=50,required=True)
    state=forms.CharField(label="state", max_length=50, required=True)
    country=forms.CharField(label="country", max_length=50, required=True)
    zip=forms.CharField(label="zpcode",max_length=10,required=True)



class PasswordForm(forms.Form):
    old_password=forms.CharField(label='old password',widget=forms.PasswordInput(),min_length=5,max_length=25,required=True)
    new_password = forms.CharField(label='new Password',widget=forms.PasswordInput(),min_length=5,max_length=25,required=True)
    email=forms.EmailField(label="email", max_length=45,required=True)