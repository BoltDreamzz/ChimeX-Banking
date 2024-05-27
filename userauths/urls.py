# urls.py
from django.urls import path
from . import views

app_name = "userauths"

urlpatterns = [
    path('splash/', views.splash, name='splash'),
    path('register/', views.signup_view, name='register'),
    path('profile/', views.profile, name='profile'),
    path('set-pin/', views.set_pin, name='set_pin'),
    path('enter-pin/', views.enter_pin, name='enter_pin'),
    path('finish/', views.finish, name='finish'),
    path('verify-otp/<int:user_id>/', views.verify_otp, name='verify-otp'),

    path('login/', views.login_view, name="login"),

    # Add similar URLs for signup, logout, etc.
]
