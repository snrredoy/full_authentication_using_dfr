from django.shortcuts import render
from rest_framework.views import APIView
from google_login.serializers import GoogleSerializer, GithubSerializer
from rest_framework.response import Response
from rest_framework import status
from google_login.utils import register_with_google
# Create your views here.

class GoogleLoginView(APIView):
    def post(self,request):
        serializer = GoogleSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            data = (serializer.validated_data)['access_token']
            return Response({
                'status':status.HTTP_200_OK,
                'success':True,
                'message':'Login successful.',
                'data':data
            },status=status.HTTP_200_OK)
        return Response({
            'status':status.HTTP_400_BAD_REQUEST,
            'success':False,
            'message':'Login failed.',
            'data':serializer.errors
        },status=status.HTTP_400_BAD_REQUEST)


class GithubLoginView(APIView):
    def post(self,request):
        serializer = GithubSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            data = (serializer.validated_data)['code']
            return Response({
                'status':status.HTTP_200_OK,
                'success':True,
                'message':'Login successful.',
                'data':data
            },status=status.HTTP_200_OK)
        return Response({
            'status':status.HTTP_400_BAD_REQUEST,
            'success':False,
            'message':'Login failed.',
            'data':serializer.errors
        },status=status.HTTP_400_BAD_REQUEST)
