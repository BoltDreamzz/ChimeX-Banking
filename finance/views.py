from django.shortcuts import render


# Create your views here.
def index(request):
    return render(request, "finance/home.html")


def bank(request):
    return render(request, "finance/bank.html")


def connect_bank(request):
    return render(request, "finance/connect_bank.html")


def send_money(request):
    return render(request, "finance/send_money.html")
