from django.contrib import admin
from django.urls import path,include
from .views import *
urlpatterns = [
    path('login/',LoginView.as_view()),
    path('signup/',RegistrationView.as_view()),
    path('logout/',LogoutUserView.as_view()),
    path('check-token/', CheckTokenStatus.as_view() )
]