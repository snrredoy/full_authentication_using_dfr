from django.urls import path
from . import views

urlpatterns = [
    path('', views.GoogleLoginView.as_view(), name='google-login'),
]
