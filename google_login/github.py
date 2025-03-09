import requests
from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed

class Github():
    @staticmethod
    def exchange_code(code):
        params = {
            'client_id': settings.GITHUB_CLIENT_ID,
            'client_secret': settings.GITHUB_CLIENT_SECRET,
            'code': code
        }
        get_access_token = requests.post("https://github.com/login/oauth/access_token", params=params, headers={'Accept': 'application/json'})
        data= get_access_token.json()
        token = data.get('access_token')
        return token

    
    # @staticmethod
    # def get_github_user(access_token):
    #     try:
    #         headers = {'Authorization': f'Bearer {access_token}'}
    #         res = requests.get("https://api.github.com/user", headers=headers)
    #         user = res.json()
    #         return user
    #     except :
    #         raise AuthenticationFailed("Token is invalid")
    @staticmethod
    def get_github_user(access_token):
        try:
            headers = {'Authorization': f'Bearer {access_token}'}
            user_res = requests.get("https://api.github.com/user", headers=headers)
            if user_res.status_code != 200:
                raise AuthenticationFailed("Invalid GitHub token")
            user = user_res.json()

            email = user.get('email')
            if not email:
                email_res = requests.get("https://api.github.com/user/emails", headers=headers)
                if email_res.status_code == 200:
                    emails = email_res.json()
                    email = next((e['email'] for e in emails if e['primary']), None)
            if not email:
                email = f"{user['login']}@github.com"

            return {
                'name': user.get('name', user['login']),
                'email': email,
            }
        except requests.exceptions.RequestException as e:
            raise AuthenticationFailed(f"Failed to fetch GitHub user: {str(e)}")