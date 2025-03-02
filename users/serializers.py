from django.contrib.sites.shortcuts import get_current_site
from rest_framework import serializers
from .models import User
from django.contrib.auth import authenticate
from django.urls import reverse
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import smart_str, force_str, smart_bytes
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import send_code_to_email, send_normal_email
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError

class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only = True)
    confirm_password = serializers.CharField(write_only = True)

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name', 'password', 'confirm_password']

    def validate(self, attrs):
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')

        if password != confirm_password:
            raise serializers.ValidationError('Password must be match')
        
        return attrs

    def create(self, validated_data):
        user = User.objects.create_user(
            email = validated_data.get('email'),
            first_name = validated_data.get('first_name'),
            last_name = validated_data.get('last_name'),
            password = validated_data.get('password')
        )
        return user

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    refresh_token = serializers.CharField(read_only=True)
    access_token = serializers.CharField(read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'refresh_token', 'access_token']

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')

        user = authenticate(email=email, password=password)

        if not user:
            raise AuthenticationFailed('Invalid credentials')

        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')

        refresh = RefreshToken.for_user(user)
        return {
            'email': user.email,
            'refresh_token': str(refresh),
            'access_token': str(refresh.access_token),
        }

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uuid = urlsafe_base64_encode(smart_bytes(user.id))
            token= PasswordResetTokenGenerator().make_token(user)
            request = self.context.get('request')
            current_site = get_current_site(request).domain
            relative_link = reverse('reset-password-confirm', kwargs={'uuid':uuid , 'token':token})
            absolute_url = f'http://{current_site}{relative_link}'
            email_body = f"Hello {user.first_name},\n\nClick on the link below to reset your password.\n\n{absolute_url}\n\nThank you for signing up on {current_site}"
            data = {
                'body': email_body,
                'subject': "Reset your password",
                'to': [user.email]
            }
            send_normal_email(data)
        
        return super().validate(attrs)


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)
    confirm_password = serializers.CharField(write_only=True)
    uuid = serializers.CharField(write_only=True)
    token = serializers.CharField(write_only=True)

    class Meta:
        fields = ['password', 'confirm_password', 'uuid', 'token']
    
    def validate(self, attrs):
        uuid = attrs.get('uuid')
        token = attrs.get('token')
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')

        if password != confirm_password:
            raise serializers.ValidationError('Password must be match')

        try:
            user_id = force_str(urlsafe_base64_decode(uuid))
            user = User.objects.get(id=user_id)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError('The reset link is invalid', 401)

        if not PasswordResetTokenGenerator().check_token(user, token):
            raise AuthenticationFailed('The reset link is invalid', 401)
        
        try:
            validate_password(password, user=user)
        except DjangoValidationError as e:
            raise serializers.ValidationError({
                'password': list(e.messages)
            })
        return attrs

    def save(self, **kwargs):
        password = self.validated_data['password']
        uuid = self.validated_data['uuid']

        user_id = force_str(urlsafe_base64_decode(uuid))
        user = User.objects.get(id=user_id)
        user.set_password(password)
        user.save()
        return user


class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(write_only=True)

    def validate(self, attrs):
        self.refresh_token = attrs.get('refresh_token')
        return attrs

    def save(self, **kwargs):
        try:
            token = RefreshToken(self.token)
            token.blacklist()
        except Exception as e:
            return serializers.ValidationError(str(e))