from django.urls import path
from . import views

urlpatterns = [
    path('', views.GoogleLoginView.as_view(), name='google-login'),
    path('github/', views.GithubLoginView.as_view(), name='github-login'),
]
