from django.urls import path
from .views import *

urlpatterns = [
    path('users', user_listing, name='user-listing'),
    path('articles', ArticleListView.as_view(), name='article-list'),
]
