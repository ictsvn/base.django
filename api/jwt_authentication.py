from backend.models import User
from rest_framework import authentication, exceptions
from rest_framework_simplejwt.state import token_backend

# Middleware to handle firebase authentication's IdToken


class CustomJWTAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        try:
            token = request.META.get('HTTP_AUTHORIZATION', " ").split(' ')[1]
            data = {'token': token}

            valid_data = token_backend.decode(token, verify=True)
            user = User.objects.get(id=valid_data['user_id'])
            return (user, None)  # authentication successful
        except Exception:
            raise exceptions.AuthenticationFailed({
                'message': 'Invalid or missing token in header'
            })
