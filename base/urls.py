"""base URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.10/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
import os
from django.urls import include, path
from django.contrib import admin
from django.conf import settings
from graphene_django.views import GraphQLView
from django.views.generic import TemplateView
import sys
from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions

admin.site.site_header = os.environ.get(
    'ADMIN_SITE_HEADER') or 'Django administration'

urlpatterns = [
    path('', include('backend.urls')),
    path('api/', include('api.urls')),
    path('admin/', admin.site.urls),
    path('graphql', GraphQLView.as_view(graphiql=True)),
]


# Schemas
schema_view = get_schema_view(
    openapi.Info(
        title="Snippets API",
        default_version='v1',
        description="Test description",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="contact@snippets.local"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)


urlpatterns = urlpatterns + [
    path('schema/swagger.json',
         schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('schema/swagger.yaml',
         schema_view.without_ui(cache_timeout=0), name='schema-yaml'),
    path('schema/swagger/', schema_view.with_ui('swagger',
                                                cache_timeout=0), name='schema-swagger-ui'),
    path('schema/redoc/', schema_view.with_ui('redoc',
                                              cache_timeout=0), name='schema-redoc'),
]
