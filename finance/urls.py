# urls.py
from django.urls import path
from . import views

app_name = "finance"

urlpatterns = [
    path('', views.index, name='index'),
    # connect_bank.html
    path('bank/', views.bank, name='bank'),

    path('connect-bank/', views.connect_bank, name='connect_bank'),
    path('send-money/', views.send_money, name='send_money'),

]
