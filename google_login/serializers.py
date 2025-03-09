from rest_framework import serializers
from google_login.utils import Google, register_with_google
from google_login.github import Github
from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed

class GoogleSerializer(serializers.Serializer):
    access_token = serializers.CharField()

    def validate_access_token(self, access_token):
        user_data = Google.validate(access_token)
        try:
            user_data['sub']
        except KeyError:
            raise AuthenticationFailed('Invalid token')
        
        if user_data['aud'] != settings.GOOGLE_CLIENT_ID:
            raise AuthenticationFailed("Could not verify Google token")
        
        user_id = user_data['sub']
        email = user_data['email']
        first_name = user_data['given_name']
        last_name = user_data['family_name']
        provider = 'google'

        return register_with_google(provider, email, first_name, last_name)


# class GithubSerializer(serializers.Serializer):
#     code = serializers.CharField()

#     def validate_code(self, code):
#         access_token = Github.exchange_code(code)
#         print(access_token)

#         if access_token:
#             user_data = Github.get_github_user(access_token)
#             print(user_data)

#             full_name = user_data['name']
#             email = user_data['email']
#             names = full_name.split(" ")
#             first_name = names[0]
#             last_name = names[1]
#             provider = 'github'

#             return register_with_google(provider, email, first_name, last_name)

class GithubSerializer(serializers.Serializer):
    code = serializers.CharField()

    def validate_code(self, code):
        access_token = Github.exchange_code(code)
        if access_token:
            user_data = Github.get_github_user(access_token)
            full_name = user_data['name']
            email = user_data['email']
            names = full_name.split(" ") if full_name else ["GitHub", "User"]
            first_name = names[0]
            last_name = names[-1] if len(names) > 1 else "User"
            provider = 'github'
            return register_with_google(provider, email, first_name, last_name)
        raise AuthenticationFailed("Invalid GitHub code")