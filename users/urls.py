from django.urls import path
from . import views
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('signup/', views.UserRegisterView.as_view(), name='user-register'),
    path('verify-email/', views.VerifyUserEmail.as_view(), name='verify-email'),
    path('login/', views.LoginView.as_view(), name='user-login'),
    path('forgot-password/', views.PasswordResetRequestView.as_view(), name='forgot-password'),
    path('reset-password-confirm/<uuid>/<token>/', views.PasswordResetConfirmView.as_view(), name='reset-password-confirm'),
    path('set-new-password/', views.SetNewPasswordView.as_view(), name='set-new-password'),
    path('logout/', views.LogoutView.as_view(), name='user-logout'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token-refresh'),
]