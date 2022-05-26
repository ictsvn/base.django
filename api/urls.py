from drf_yasg import openapi
from drf_yasg.views import get_schema_view
from rest_framework import permissions
from django.urls import path
from rest_framework import routers
from . import views
from .views import LogEntryViewSet, UserViewSet

schema_view = get_schema_view(
   openapi.Info(
      title="API docs",
      default_version='v1',
      description="API docs"
   ),
   public=True,
   permission_classes=[permissions.AllowAny],
   authentication_classes=[]
)

router = routers.DefaultRouter()
router.register(r'log-entry', LogEntryViewSet)
router.register(r'user', UserViewSet)

urlpatterns = [
    path('', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('sign-in', views.signin.as_view(), name='sign_in'),
    path('sign-up', views.signup.as_view(), name='sign_up'),
    path('token/refresh', views.refresh.as_view(), name='token_refresh'),
    path('user-profile', views.user_profile_api.as_view(), name='user_profile_api'),
    path('social-login', views.social_login.as_view(), name='social_login'),
]
