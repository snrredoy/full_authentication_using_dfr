from google.auth.transport import requests
from google.oauth2 import id_token
from users.models import User
from django.contrib.auth import authenticate
from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed