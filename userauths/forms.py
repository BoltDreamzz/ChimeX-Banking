from django import forms
from .models import User
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm

from .models import CountryField


class PinForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['pin']


class CountrylForm(forms.ModelForm):
    country = CountryField()

    class Meta:
        model = User
        fields = ['country']


class SignupForm(UserCreationForm):
    class Meta:
        model = User
        fields = ["username", "email", "password1", "password2"]

    username = forms.CharField(widget=forms.TextInput(attrs={
        "placeholder": "Username",
        "class": "form-control bg-body-tertiary"
    }))

    email = forms.EmailField(widget=forms.EmailInput(attrs={
        "placeholder": "email",
        "class": "form-control bg-body-tertiary"
    }))

    password1 = forms.CharField(widget=forms.PasswordInput(attrs={
        "placeholder": "password",
        "class": "form-control bg-body-tertiary"
    }))
    password2 = forms.CharField(widget=forms.PasswordInput(attrs={
        "placeholder": "repeat password",
        "class": "form-control bg-body-tertiary"
    }))


class LoginForm(AuthenticationForm):
    username = forms.CharField(widget=forms.TextInput(attrs={
        "class": "form-control bg-body-tertiary",
        "placeholder": "email"
    }))

    password = forms.CharField(widget=forms.PasswordInput(attrs={
        "class": "form-control bg-body-tertiary",
        "placeholder": "password"
    }))
