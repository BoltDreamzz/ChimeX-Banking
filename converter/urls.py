# converter/urls.py

from django.urls import path

from . import views

urlpatterns = [
    path('convert/', views.convert_currency, name='convert_currency'),
]
