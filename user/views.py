from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.views import APIView
from rest_framework import status
from .serializers import *
from django.shortcuts import get_object_or_404
from rest_framework.permissions import IsAuthenticated
# from .models import User
from rest_framework.exceptions import AuthenticationFailed
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed
import datetime
from django.conf import settings
import jwt
from .permissions import JWTAuthentication

def generate_jwt_token(id):
    payload = {
        'id': id,
            'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=60),
            'iat': datetime.datetime.now(datetime.timezone.utc)
    }

    token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

    
    jwt_token =  token,  payload['exp'] 

    return jwt_token
 

class RegistrationView(APIView):
    def post(self,request):
        response = dict()
        serializers = UserAuthSerializer(data=request.data)
        if serializers.is_valid():
            serializers.save()
            response["data"] = serializers.data
            response["status"] = status.HTTP_201_CREATED
            response["msg"] = "Congo. You're successfully registered"
            return Response(response)          

        return Response(serializers.errors) 

    def get(self,request):
        users = User.objects.all()
        serializer = UserAuthSerializer(users,many=True)
        return Response(serializer.data)

        
class LoginView(APIView):
 def post(self, request, *args, **kwargs):        
        email = request.data.get('email', '')
        password = request.data.get('password', '')
        user = get_object_or_404(User,email=email)
        token, expiry = generate_jwt_token(user.id)
        if not user:
            raise AuthenticationFailed("user not found")

        if not user.check_password(password):
            raise AuthenticationFailed("incorrect password")

        return Response(status=status.HTTP_200_OK, data= { "token" :  token, "expiry": expiry, "msg" : "login successfully"}) 



class LogoutUserView(APIView):
    def get(self, request, *args, **kwargs):
        return Response({"status": status.HTTP_200_OK })        


class CheckTokenStatus(APIView):
    permission_classes = [JWTAuthentication]

    def get(self, request, **kwargs):
        return Response(status = status.HTTP_200_OK, data = {"msg" : "Token is active"})
