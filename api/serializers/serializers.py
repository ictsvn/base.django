from rest_framework import serializers, viewsets, status
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.authtoken.models import Token

from backend.models import User
import django.contrib.auth.password_validation as validators
from django.core import exceptions
from django.conf import settings
from social_core.exceptions import MissingBackend
from social_core.backends.utils import get_backend


class ListPagination(PageNumberPagination):
    page_size = 20
    page_size_query_param = 'page_size'

    def paginate_queryset(self, queryset, request, view=None):
        """
        Paginate a queryset if required, either returning a
        page object, or `None` if pagination is not configured for this view.
        """
        page_size = self.get_page_size(request)
        if not page_size:
            return None

        paginator = self.django_paginator_class(queryset, page_size)
        page_number = request.query_params.get(self.page_query_param, 1)
        if page_number in self.last_page_strings:
            page_number = paginator.num_pages

        self.page = paginator.page(page_number)

        if paginator.num_pages > 1 and self.template is not None:
            # The browsable API should display pagination controls.
            self.display_page_controls = True

        self.request = request
        return list(self.page)

    def get_paginated_response(self, data, start=None, end=None):
        response_dict = {
            'data': {
                'count': self.page.paginator.count,
                'next': self.get_next_link(),
                'previous': self.get_previous_link(),
                'results': data
            }
        }
        if start is not None:
            response_dict['data']['start'] = start

        if end is not None:
            response_dict['data']['end'] = end

        return Response(response_dict)


class SignInSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=255, required=True)
    password = serializers.CharField(max_length=255, required=True, write_only=True)


class RefreshSeriarlizer(serializers.Serializer):
    refresh = serializers.CharField(max_length=255, required=True)

    def validate_refresh(self, value):
        try:
            refresh = RefreshToken(value)
            token = refresh.access_token
            return value
        except Exception:
            raise serializers.ValidationError("Invalid refresh token")


class SignUpSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=255, required=True)
    email = serializers.EmailField(required=True)
    password = serializers.CharField(max_length=255, required=True, write_only=True)

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already existed")

    def validate_password(self, value):
        try:
            # validate the password and catch the exception
            validators.validate_password(password=value)

         # the exception raised here is different than serializers.ValidationError
        except exceptions.ValidationError as e:
            raise serializers.ValidationError(list(e))


class SocialRegisterSerializer(serializers.Serializer):
    provider = serializers.CharField(max_length=255, required=True)
    access_token = serializers.CharField(required=True)

    def validate_provider(self, value):
        try:
            get_backend(settings.AUTHENTICATION_BACKENDS, value)
            return value
        except MissingBackend:
            raise serializers.ValidationError("Invalid provider, options are 'facebook', 'google-oauth2', 'apple-id'")

    def validate(self, data):
        try:
            backend = get_backend(settings.AUTHENTICATION_BACKENDS, data['provider'])
            backend_instance = backend()
            backend_instance.do_auth(data['access_token'])
            return data
        except Exception:
            raise serializers.ValidationError({"access_token": ["Invalid token"]})
