from rest_framework.views import APIView
from .serializers import UserRegisterSerializer, LoginSerializer, LogoutSerializer, ForgotPasswordSerializer, SetNewPasswordSerializer
from rest_framework.response import Response
from rest_framework import status
from .utils import send_code_to_email, send_normal_email
from .models import User, OTP
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import smart_str , DjangoUnicodeDecodeError
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.tokens import PasswordResetTokenGenerator


# Create your views here.
class UserRegisterView(APIView):
    def post(self, request):
        user = request.data
        serializer = UserRegisterSerializer(data=user)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user_data = serializer.data
            send_code_to_email(user_data['email'], request)
            return Response({
                'status':status.HTTP_201_CREATED,
                'success':True,
                'message':'Thanks for signing up. A passcode has been sent to verify your email.',
                'data':user_data
            },status=status.HTTP_201_CREATED)
        return Response({
            'status':status.HTTP_400_BAD_REQUEST,
            'success':False,
            'message':'User not created',
            'data':serializer.errors
        },status=status.HTTP_400_BAD_REQUEST)

class VerifyUserEmail(APIView):
    def post(self, request):
        otp = request.data.get('otp')
        email = request.data.get('email')

        if not otp or not email:
            return Response({
                'status':status.HTTP_400_BAD_REQUEST,
                'success':False,
                'message':'OTP or email not found'
                }, status=status.HTTP_400_BAD_REQUEST)

        try:
            user_pass_obj = OTP.objects.select_related('user').get(otp=otp, user__email=email)
            user = user_pass_obj.user
            if user.is_verified:
                return Response({
                    'status':status.HTTP_200_OK,
                    'success': True,
                    'message': 'Account email is already verified.'
                }, status=status.HTTP_200_OK)

            user.is_verified = True
            user.save()
            user_pass_obj.delete()

            return Response({
                'status':status.HTTP_200_OK,
                'success': True,
                'message': 'Account email is verified successfully.',
                }, status=status.HTTP_200_OK)

        except OTP.DoesNotExist as e:
            return Response({
                'status':status.HTTP_400_BAD_REQUEST,
                'success': False,
                'message': 'Invalid OTP',
                'data': str(e)
                }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                'status':status.HTTP_400_BAD_REQUEST,
                'success': False,
                'message': 'An error occurred during email verification.',
                'data': str(e)
                }, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({
                'status':status.HTTP_200_OK,
                'success': True,
                'message': 'Login successful.',
                'data': serializer.data
                }, status=status.HTTP_200_OK)
        return Response({
            'status':status.HTTP_400_BAD_REQUEST,
            'success': False,
            'message': 'Login failed.',
            'data': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data, context={'request': request})
        if serializer.is_valid(raise_exception=True):
            return Response({
                'status':status.HTTP_200_OK,
                'success': True,
                'message': 'Password reset email sent.We have sent you a link to reset your password.',
                }, status=status.HTTP_200_OK)
        return Response({
            'status':status.HTTP_400_BAD_REQUEST,
            'success': False,
            'message': 'Failed to send password reset email.',
            'data': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetConfirmView(APIView):
    def get(self, request, uuid, token):
        try:
            user_id = smart_str(urlsafe_base64_decode(uuid))
            user = User.objects.get(id=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({
                    'status':status.HTTP_400_BAD_REQUEST,
                    'success': False,
                    'message': 'The reset link is invalid',
                    }, status=status.HTTP_400_BAD_REQUEST)

            return Response({
                'status':status.HTTP_200_OK,
                'success': True,
                'message': 'The reset link is valid',
                'data': {
                    'uuid': uuid,
                    'token': token
                }
                }, status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as e:
            return Response({
                'status':status.HTTP_400_BAD_REQUEST,
                'success': False,
                'message': 'The reset link is invalid',
                'data': str(e)
                }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                'status':status.HTTP_400_BAD_REQUEST,
                'success': False,
                'message': 'An error occurred during password reset.',
                'data': str(e)
                }, status=status.HTTP_400_BAD_REQUEST)


class SetNewPasswordView(APIView):
    def post(self, request):
        serializer = SetNewPasswordSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({
                'status':status.HTTP_200_OK,
                'success': True,
                'message': 'Password reset successful.',
                }, status=status.HTTP_200_OK)
        return Response({
            'status':status.HTTP_400_BAD_REQUEST,
            'success': False,
            'message': 'Password reset failed.',
            'data': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)