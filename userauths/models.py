from django.contrib.auth.models import AbstractUser
from django.db import models
import pyotp

from django_countries.fields import CountryField as DjangoCountryField


class CountryField(DjangoCountryField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('max_length', 2)
        super().__init__(*args, **kwargs)

    def formfield(self, **kwargs):
        # This method is necessary for Django to recognize this field in forms.
        defaults = {'form_class': CountryField}
        defaults.update(kwargs)
        return super().formfield(**defaults)


class User(AbstractUser):
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField()
    is_active = models.BooleanField(default=False, null=True)
    phone = models.IntegerField()
    date_of_birth = models.DateField(blank=True, null=True)

    country = CountryField()
    ssn = models.IntegerField(null=True, blank=True)
    pin = models.CharField(max_length=4, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)


# models.py


class UserOTP(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp_code = models.CharField(max_length=6)
    otp_created_at = models.DateTimeField(auto_now_add=True)

    def generate_otp(self):
        totp = pyotp.TOTP(pyotp.random_base32())
        return totp.now()

    def __str__(self):
        return f'{self.user.username} - {self.otp_code}'
