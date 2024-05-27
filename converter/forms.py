# converter/forms.py

from django import forms
from .models import Currency


class CurrencyConverterForm(forms.Form):
    amount = forms.DecimalField(label='Amount', min_value=0)
    from_currency = forms.ModelChoiceField(queryset=Currency.objects.all(), label='From Currency')
    to_currency = forms.ModelChoiceField(queryset=Currency.objects.all(), label='To Currency')
