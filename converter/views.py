# converter/views.py

from django.shortcuts import render
from .forms import CurrencyConverterForm
from forex_python.converter import CurrencyRates


def convert_currency(request):
    form = CurrencyConverterForm()
    result = None

    if request.method == 'POST':
        form = CurrencyConverterForm(request.POST)
        if form.is_valid():
            amount = form.cleaned_data['amount']
            from_currency = form.cleaned_data['from_currency'].code
            to_currency = form.cleaned_data['to_currency'].code
            currency_rates = CurrencyRates()
            conversion_rate = currency_rates.get_rate(from_currency, to_currency)
            result = amount * conversion_rate

    return render(request, 'converter/currency_converter.html', {'form': form, 'result': result})
