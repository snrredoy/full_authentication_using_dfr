from datetime import timedelta
import datetime
from django.db import models
from .managers import CustomUserManager
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin




# Create your models here.

AUTH_PROVIDERS = {
    'email': 'email',
    'google': 'google',
    'facebook': 'facebook',
    'twitter': 'twitter',
    'apple': 'apple',
    'github': 'github',
}


class User(AbstractBaseUser, PermissionsMixin):

    email = models.EmailField(unique=True)
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)

    is_verified = models.BooleanField(default=False)

    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    auth_provider = models.CharField(max_length=255, default=AUTH_PROVIDERS.get('email'))

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    objects = CustomUserManager()

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return{
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }

    def __str__(self):
        return self.email
    
    def get_full_name(self):
        return self.first_name + ' ' + self.last_name

class OTP(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length = 6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        expire = self.created_at + timedelta(minutes=5)
        if expire < datetime.now():
            return True
        return False