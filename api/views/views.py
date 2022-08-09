from rest_framework import serializers, viewsets
from django.contrib import admin

#
# Django
from django.shortcuts import render
from backend.models import User
from django.contrib.auth import authenticate
from django.http import JsonResponse
from django.core.paginator import InvalidPage

# Rest-framework
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.backends import TokenBackend

# DRF Swagger
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema

# Apps
from api.jwt_authentication import CustomJWTAuthentication
from api.serializers import (
    ListPagination,
    SignInSerializer,
    RefreshSeriarlizer,
    SignUpSerializer,
    SocialRegisterSerializer
)

from utils.oauth2 import get_facebook_user_info, get_google_user_info


class LogEntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = admin.models.LogEntry
        fields = (
            '__all__')


class LogEntryViewSet(viewsets.ModelViewSet):
    queryset = admin.models.LogEntry.objects.all()
    serializer_class = LogEntrySerializer


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        exclude = (
            'password',)

# abc


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer


authorization = openapi.Parameter('Authorization', openapi.IN_HEADER,
                                  description="Bearer <access_token>", type=openapi.TYPE_STRING)
page = openapi.Parameter('page', openapi.IN_QUERY, description="page number", type=openapi.TYPE_INTEGER)
page_size = openapi.Parameter('page_size', openapi.IN_QUERY, description="page size", type=openapi.TYPE_INTEGER)

signin_response_schema_dict = {
    "200": openapi.Response(
        description="Success",
        examples={
            "application/json": {
                "refresh": "string",
                "access": "string",
            }
        }
    ),
    "403": openapi.Response(
        description="Forbidden",
        examples={
            "application/json": {
                "message": "invalid username or password"
            }
        }
    ),
    "400": openapi.Response(
        description="Invalid",
        examples={
            "application/json": {
                "message": {
                    "username": [
                        "This field may not be blank."
                    ],
                    "password": [
                        "This field may not be blank."
                    ]
                }
            }
        }
    )
}


class signin(APIView):
    permission_classes = ()
    authentication_classes = ()

    @swagger_auto_schema(request_body=SignInSerializer, responses=signin_response_schema_dict)
    def post(self, request):
        received_json_data = request.data
        serializer = SignInSerializer(data=received_json_data)
        if serializer.is_valid():
            user = authenticate(
                request,
                username=serializer.validated_data['username'],
                password=serializer.validated_data['password'])
            if user is not None:
                refresh = RefreshToken.for_user(user)
                return JsonResponse({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                }, status=200)
            else:
                return JsonResponse({
                    'message': 'invalid username or password',
                }, status=403)
        else:
            return JsonResponse({'message': serializer.errors}, status=400)


refresh_response_schema_dict = {
    "200": openapi.Response(
        description="Success",
        examples={
            "application/json": {
                'access': 'string'
            }
        }
    ),
    "400": openapi.Response(
        description="Invalid",
        examples={
            "application/json": {
                "message": {
                    "refresh": [
                        "Invalid refresh token"
                    ]
                }
            }
        }
    )
}


class refresh(APIView):
    permission_classes = ()
    authentication_classes = ()

    @swagger_auto_schema(request_body=RefreshSeriarlizer, responses=refresh_response_schema_dict)
    def post(self, request):
        received_json_data = request.data
        serializer = RefreshSeriarlizer(data=received_json_data)
        if serializer.is_valid():
            refresh = RefreshToken(received_json_data['refresh'])

            if refresh is not None:
                access_token = refresh.access_token
                return JsonResponse({
                    'access': str(access_token)
                }, status=200)
        else:
            return JsonResponse({'message': serializer.errors}, status=400)


class user_profile_api(APIView):
    permission_classes = (IsAuthenticated,)

    @swagger_auto_schema(manual_parameters=[authorization])
    def get(self, request):
        try:
            user = request.user
            return JsonResponse({
                "username": user.username,
                "email": user.email
            }, status=200)
        except Exception as e:
            return JsonResponse({'message': 'Server error'}, status=500)


signup_response_schema_dict = {
    "200": openapi.Response(
        description="Success",
        examples={
            "application/json": {
                "id": "integer",
                "username": "string",
                "email": "string"
            }
        }
    ),
    "400": openapi.Response(
        description="Invalid",
        examples={
            "application/json": {
                "message": {
                    "username": [
                        "Username already existed"
                    ],
                    "email": [
                        "This field may not be blank."
                    ],
                    "password": [
                        "This password is too short. It must contain at least 8 characters.",
                        "This password is too common.",
                        "This password is entirely numeric."
                    ]
                }
            }
        }
    )
}


class signup(APIView):
    permission_classes = ()
    authentication_classes = ()

    @swagger_auto_schema(request_body=SignUpSerializer, responses=signup_response_schema_dict)
    def post(self, request):
        received_json_data = request.data
        serializer = SignUpSerializer(data=received_json_data)
        if serializer.is_valid():
            user = User.objects.create_user(username=received_json_data["username"], email=received_json_data["email"])
            user.set_password(received_json_data["password"])
            user.save()

            return JsonResponse({"id": user.id, "username": user.username, "email": user.email}, status=200)
        else:
            return JsonResponse({"message": serializer.errors}, status=400)


social_response_schema_dict = {
    "200": openapi.Response(
        description="Success",
        examples={
            "application/json": {
                'refresh': "string",
                'access': "string",
            }
        }
    ),
    "400": openapi.Response(
        description="Invalid",
        examples={
            "application/json": {
                "message": {
                    "provider": [
                        "This field is required."
                    ],
                    "access_token": [
                        "This field is required."
                    ],
                }
            }
        }
    )
}


class social_login(APIView):
    permission_classes = ()
    authentication_classes = ()

    @swagger_auto_schema(request_body=SocialRegisterSerializer, responses=social_response_schema_dict)
    def post(self, request):
        received_json_data = request.data
        serializer = SocialRegisterSerializer(data=received_json_data)
        if serializer.is_valid():
            provider = serializer.validated_data['provider']
            access_token = serializer.validated_data['access_token']
            if provider == 'google-oauth2':
                user_infos = get_google_user_info(access_token)
                user, created = User.objects.get_or_create(
                    email=user_infos['email'],
                    defaults={
                        'username': user_infos['username'],
                        'first_name': user_infos['first_name'],
                        'last_name': user_infos['last_name']
                    }
                )
            elif provider == 'facebook':
                user_infos = get_facebook_user_info(access_token)
                user, created = User.objects.get_or_create(
                    username=user_infos['username'],
                    defaults={
                        'email': user_infos['email'],
                        'first_name': user_infos['first_name'],
                        'last_name': user_infos['last_name']
                    }
                )
            refresh = RefreshToken.for_user(user)
            return JsonResponse({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=200)
        else:
            return JsonResponse({'message': serializer.errors}, status=400)
