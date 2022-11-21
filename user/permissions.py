import jwt
from django.conf import settings
from rest_framework import authentication, exceptions, permissions
from .models import *
import datetime
from django.contrib.auth.models import User 


class JWTAuthentication(permissions.BasePermission):
    authentication_header_prefix = 'Token'

    def has_permission(self, request, view):
        auth_token = request.headers.get('Authorization')
        return self._authenticate_credentials(request, auth_token)

    def _authenticate_credentials(self, request, token):
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, options={"verify_signature": False},  algorithms=['HS256'])
        except:
            msg = 'Invalid authentication. Could not decode token.'
            raise exceptions.AuthenticationFailed(msg)

        expiry = payload.get("exp", False)
        if expiry:
            timestamp = datetime.datetime.now().timestamp() - int(expiry)
            if timestamp <= 0 :
                return True

        raise exceptions.AuthenticationFailed("You're session has been terminated !")
